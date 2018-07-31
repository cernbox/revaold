package api

import (
	"fmt"
)

type ErrorCode string

const (
	// StorageNotFoundErrorCode is used when a resource is not found.
	StorageNotFoundErrorCode ErrorCode = "STORAGE_ERROR_NOT_FOUND"

	// StorageAlreadyExistsErrorCode is used when a resource already exists.
	StorageAlreadyExistsErrorCode ErrorCode = "STORAGE_ERROR_ALREADY_EXISTS"

	// StoragePermissionDeniedErrorCode is used when it is not possible to acces the resource.
	StoragePermissionDeniedErrorCode ErrorCode = "STORAGE_ERROR_PERMISSION_DENIED"

	// ContextUserRequired requires an pkg.User object in the context
	ContextUserRequiredError ErrorCode = "CONTEXT_USER_REQUIRED"

	// PathInvalidError is used when a path is invalid, like not begging with /
	PathInvalidError ErrorCode = "PATH_INVALID_ERROR"

	// PublicLinkNotFoundErrorCode is used when a resource is not found.
	PublicLinkNotFoundErrorCode ErrorCode = "PUBLIC_LINK_NOT_FOUND"

	PublicLinkInvalidExpireDateErrorCode ErrorCode = "PUBLIC_LINK_INVALID_EXPIRE_DATE"

	PublicLinkInvalidPasswordErrorCode ErrorCode = "PUBLIC_LINK_INVALID_PASSWORD"

	// FolderShareNotFoundErrorCode is used when a resource is not found.
	FolderShareNotFoundErrorCode ErrorCode = "FOLDER_SHARE_NOT_FOUND"

	// StorageOperationNotSupported is used when some operation is not available on
	// the storage, like emptying the recycle bin
	StorageNotSupportedErrorCode ErrorCode = "STORAGE_NOT_SUPPORTED"

	UserNotFoundErrorCode ErrorCode = "USER_NOT_FOUND"

	TokenInvalidErrorCode ErrorCode = "TOKEN_INVALID"

	// ProjectNotFoundErrorCode is used when a resource is not found.
	ProjectNotFoundErrorCode ErrorCode = "PROJECT_NOT_FOUND"

	UnknownError ErrorCode = "UNKNOWN"
)

func NewError(code ErrorCode) AppError {
	return AppError{Code: code}
}

type AppError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e AppError) WithMessage(msg string) AppError {
	e.Message = msg
	return e
}

func (e AppError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	} else {
		return fmt.Sprintf("%s", e.Code)
	}
}

func IsErrorCode(err error, code ErrorCode) bool {
	apiErr, ok := err.(AppError)
	if !ok {
		return false
	}
	return apiErr.Code == code
}
