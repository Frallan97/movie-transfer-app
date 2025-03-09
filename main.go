package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
)

// Global S3 client
var s3Client *s3.Client

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	awsRegion := os.Getenv("AWS_REGION")
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	if awsRegion == "" || s3BucketName == "" {
		log.Fatalf("Missing required environment variables: AWS_REGION, S3_BUCKET_NAME")
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion))
	if err != nil {
		log.Fatalf("Unable to load AWS SDK config: %v", err)
	}
	s3Client = s3.NewFromConfig(cfg)

	commonChain := alice.New(logMiddleware, corsMiddleware)
	http.Handle("/create-folder", commonChain.Then(http.HandlerFunc(createFolderHandler)))
	http.Handle("/folders", commonChain.Then(http.HandlerFunc(listFoldersHandler)))
	http.Handle("/upload", commonChain.Then(http.HandlerFunc(uploadHandler)))
	http.Handle("/download", commonChain.Then(http.HandlerFunc(downloadHandler)))
	http.Handle("/delete", commonChain.Then(http.HandlerFunc(deleteHandler)))
	http.Handle("/list", commonChain.Then(http.HandlerFunc(listFilesHandler)))

	fmt.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// logMiddleware logs each request.
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s took %s from %s", r.Method, r.URL.Path, time.Since(start), r.RemoteAddr)
	})
}

// corsMiddleware adds CORS headers.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // For development only.
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// createFolderHandler creates a new folder in S3 by putting an empty object with a trailing slash.
func createFolderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Folder string `json:"folder"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	folderName := strings.TrimSpace(req.Folder)
	if folderName == "" {
		http.Error(w, "Folder name required", http.StatusBadRequest)
		return
	}
	key := folderName + "/"
	_, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(os.Getenv("S3_BUCKET_NAME")),
		Key:    aws.String(key),
		Body:   strings.NewReader(""),
	})
	if err != nil {
		http.Error(w, "Failed to create folder: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Folder created: %s", folderName)
}

// listFoldersHandler lists folders using delimiter.
func listFoldersHandler(w http.ResponseWriter, r *http.Request) {
	bucket := os.Getenv("S3_BUCKET_NAME")
	resp, err := s3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Delimiter: aws.String("/"),
	})
	if err != nil {
		http.Error(w, "Failed to list folders: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var folders []string
	for _, prefix := range resp.CommonPrefixes {
		if prefix.Prefix != nil {
			folders = append(folders, strings.TrimSuffix(*prefix.Prefix, "/"))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(folders)
}

// uploadHandler supports multiple file uploads with an optional folder.
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Error parsing multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}
	folder := strings.TrimSpace(r.FormValue("folder"))
	form := r.MultipartForm
	fileHeaders := form.File["file"]
	if len(fileHeaders) == 0 {
		http.Error(w, "No files provided", http.StatusBadRequest)
		return
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []string
	var errors []string

	for _, fh := range fileHeaders {
		wg.Add(1)
		go func(fh *multipart.FileHeader) {
			defer wg.Done()
			file, err := fh.Open()
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("Error opening file %s: %v", fh.Filename, err))
				mu.Unlock()
				return
			}
			defer file.Close()
			key := fh.Filename
			if folder != "" {
				key = folder + "/" + fh.Filename
			}
			url, err := uploadFileToS3(file, key)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("Error uploading file %s: %v", fh.Filename, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			results = append(results, url)
			mu.Unlock()
		}(fh)
	}
	wg.Wait()
	response := map[string]interface{}{
		"uploaded": results,
		"errors":   errors,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// downloadHandler handles downloading one or multiple files with optional folder.
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	folder := strings.TrimSpace(r.URL.Query().Get("folder"))
	filenameParam := r.URL.Query().Get("filename")
	if filenameParam == "" {
		http.Error(w, "Filename query parameter is required", http.StatusBadRequest)
		return
	}
	filenames := strings.Split(filenameParam, ",")
	for i, f := range filenames {
		f = strings.TrimSpace(f)
		decoded, err := url.QueryUnescape(f)
		if err != nil {
			decoded = f
		}
		if folder != "" {
			decoded = folder + "/" + decoded
		}
		filenames[i] = decoded
	}
	if len(filenames) == 1 {
		url, err := generatePresignedURL(filenames[0])
		if err != nil {
			http.Error(w, "Failed to generate download link: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Download URL: %s", url)
	} else {
		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)
		for _, filename := range filenames {
			resp, err := s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
				Bucket: aws.String(os.Getenv("S3_BUCKET_NAME")),
				Key:    aws.String(filename),
			})
			if err != nil {
				http.Error(w, "Failed to get file "+filename+": "+err.Error(), http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()
			// Store only the file name in the ZIP archive.
			parts := strings.Split(filename, "/")
			displayName := parts[len(parts)-1]
			zipFile, err := zipWriter.Create(displayName)
			if err != nil {
				http.Error(w, "Failed to create zip entry for "+filename+": "+err.Error(), http.StatusInternalServerError)
				return
			}
			if _, err = io.Copy(zipFile, resp.Body); err != nil {
				http.Error(w, "Failed to write file "+filename+" to zip: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if err := zipWriter.Close(); err != nil {
			http.Error(w, "Failed to finalize zip file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=\"files.zip\"")
		w.Write(buf.Bytes())
	}
}

// deleteHandler handles deleting one or multiple files with optional folder.
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var filenames []string
	if err := json.NewDecoder(r.Body).Decode(&filenames); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	folder := strings.TrimSpace(r.URL.Query().Get("folder"))
	for i, f := range filenames {
		f = strings.TrimSpace(f)
		decoded, err := url.QueryUnescape(f)
		if err != nil {
			decoded = f
		}
		if folder != "" {
			decoded = folder + "/" + decoded
		}
		filenames[i] = decoded
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var deleted []string
	var errors []string
	for _, f := range filenames {
		wg.Add(1)
		go func(fn string) {
			defer wg.Done()
			if err := deleteFileFromS3(fn); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Sprintf("Failed to delete %s: %v", fn, err))
				mu.Unlock()
			} else {
				mu.Lock()
				deleted = append(deleted, fn)
				mu.Unlock()
			}
		}(f)
	}
	wg.Wait()
	response := map[string]interface{}{
		"deleted": deleted,
		"errors":  errors,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// listFilesHandler lists files in a folder.
// If a "folder" query parameter is provided, only files with that prefix are listed (and prefix removed).
func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	folder := strings.TrimSpace(r.URL.Query().Get("folder"))
	var prefix string
	if folder != "" {
		prefix = folder + "/"
	}
	resp, err := s3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(os.Getenv("S3_BUCKET_NAME")),
		Prefix: aws.String(prefix),
	})
	if err != nil {
		http.Error(w, "Failed to list files in S3: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var files []string
	for _, item := range resp.Contents {
		name := *item.Key
		if prefix != "" {
			name = strings.TrimPrefix(name, prefix)
		}
		// Only show non-empty names (skip folder placeholder objects)
		if name != "" {
			files = append(files, name)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func uploadFileToS3(file multipart.File, key string) (string, error) {
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	_, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String(key),
		Body:   file,
	})
	if err != nil {
		return "", err
	}
	fileURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", s3BucketName, os.Getenv("AWS_REGION"), key)
	return fileURL, nil
}

func generatePresignedURL(key string) (string, error) {
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	presignClient := s3.NewPresignClient(s3Client)
	req, err := presignClient.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func deleteFileFromS3(key string) error {
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	_, err := s3Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String(key),
	})
	return err
}
