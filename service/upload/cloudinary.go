package upload

import (
	"context"
	"fmt"
	"mime/multipart"
	"time"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
)

type CloudinaryService struct {
	cld *cloudinary.Cloudinary
}

func NewCloudinaryService(cloudName, apiKey, apiSecret string) (*CloudinaryService, error) {
	cld, err := cloudinary.NewFromParams(cloudName, apiKey, apiSecret)
	if err != nil {
		return nil, err
	}

	return &CloudinaryService{cld: cld}, err
}

func (c *CloudinaryService) UploadImage(file multipart.File, folder, filename string) (string, error) {
	ctx := context.Background()
	publicID := fmt.Sprintf("%s/%s-%d", folder, filename, time.Now().Unix())

	resp, err := c.cld.Upload.Upload(ctx, file, uploader.UploadParams{
		PublicID: publicID,
		Folder:   folder,
	})
	if err != nil {
		return "", err
	}

	return resp.SecureURL, nil
}
