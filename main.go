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
	// Load environment variables from .env
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
	http.Handle("/upload", commonChain.Then(http.HandlerFunc(uploadHandler)))
	http.Handle("/download", commonChain.Then(http.HandlerFunc(downloadHandler)))
	http.Handle("/delete", commonChain.Then(http.HandlerFunc(deleteHandler)))
	http.Handle("/list", commonChain.Then(http.HandlerFunc(listFilesHandler)))

	fmt.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s took %s from %s", r.Method, r.URL.Path, time.Since(start), r.RemoteAddr)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// uploadHandler handles single or multiple file uploads concurrently.
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Error parsing multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

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
			url, err := uploadFileToS3(file, fh.Filename)
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

// downloadHandler handles downloading one or multiple files.
// It expects a query parameter "filename" with a comma-separated list.
// It URL-decodes each file name so that names with spaces/special characters match the S3 keys.
func downloadHandler(w http.ResponseWriter, r *http.Request) {
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
			decoded = f // fallback to original if error
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
			zipFile, err := zipWriter.Create(filename)
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

// deleteHandler handles deleting one or multiple files.
// It expects a JSON array of file names in the request body.
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
	// URL-decode each file name and trim whitespace.
	for i, f := range filenames {
		decoded, err := url.QueryUnescape(strings.TrimSpace(f))
		if err != nil {
			decoded = strings.TrimSpace(f) // fallback if decoding fails
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


// listFilesHandler lists all files in the S3 bucket.
func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	files, err := listFilesInS3()
	if err != nil {
		http.Error(w, "Failed to list files in S3: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func uploadFileToS3(file multipart.File, filename string) (string, error) {
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	_, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:          aws.String(s3BucketName),
		Key:             aws.String(filename),
		Body:            file,
		ContentEncoding: aws.String("gzip"), // inform that the file is gzipped
	})
	if err != nil {
		return "", err
	}
	fileURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", s3BucketName, os.Getenv("AWS_REGION"), filename)
	return fileURL, nil
}


func generatePresignedURL(filename string) (string, error) {
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	presignClient := s3.NewPresignClient(s3Client)
	req, err := presignClient.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String(filename),
	})
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func listFilesInS3() ([]string, error) {
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	resp, err := s3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(s3BucketName),
	})
	if err != nil {
		return nil, err
	}
	var files []string
	for _, item := range resp.Contents {
		files = append(files, *item.Key)
	}
	return files, nil
}

func deleteFileFromS3(filename string) error {
	s3BucketName := os.Getenv("S3_BUCKET_NAME")
	_, err := s3Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(s3BucketName),
		Key:    aws.String(filename),
	})
	return err
}
