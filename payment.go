package spworlds

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// True if request is valid;
// False if not
func (c *Client) ValidateRequest(req http.Request) (bool, error) {
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return false, errors.New("failed to read request body: " + err.Error())
	}
	defer req.Body.Close()

	hashHeader := req.Header.Get("X-Body-Hash")
	if hashHeader == "" {
		return false, errors.New("missing signature header")
	}

	mac := hmac.New(sha256.New, []byte(c.Token))
	mac.Write(bodyBytes)
	computedHash := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	providedHash, err := base64.StdEncoding.DecodeString(hashHeader)
	if err != nil {
		return false, errors.New("invalid base64 signature: " + err.Error())
	}

	if !hmac.Equal([]byte(computedHash), providedHash) {
		return false, nil
	}

	return true, nil
}

type PaymentData struct {
	// Ник игрока, который совершил оплату.
	Payer string `json:"payer"`
	// Стоимость покупки.
	Amount int `json:"amount"`
	// Data -> Payload
	// Данные, которые вы отдали при создании запроса на оплату.
	Payload string `json:"payload"`
}

// Before executing validate request using ValidateRequest
func (c *Client) PaymentData(req http.Request) (*PaymentData, error) {
	var resp PaymentData

	respBody, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if err := c.parseResponse(respBody, resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

type ReceivementData struct {
	// Уникальный ID транзакции.
	ID string `json:"id"`
	// Сумма транзакции.
	Amount int `json:"amount"`
	// Тип транзакции.
	// TODO: make string enum
	Type   string `json:"type"`
	Sender *struct {
		// Ник отправителя (если есть).
		Username *string
		// Номер карты отправителя (если есть).
		Number *string
	} `json:"sender"`
	Recivier *struct {
		// Ник получателя (если есть).
		Username *string
		// Номер карты получателя (если есть).
		Number *string
	} `json:"receiver"`
	// Комментарий к транзакции.
	Comment string `json:"comment"`
	// Дата создания транзакции.
	CreatedAt string `json:"createdAt"`
}

// Before executing validate request using ValidateRequest
func (c *Client) ReceivementData(req http.Request) (*ReceivementData, error) {
	var resp ReceivementData

	respBody, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if err := c.parseResponse(respBody, resp); err != nil {
		return nil, err
	}

	return &resp, nil
}
