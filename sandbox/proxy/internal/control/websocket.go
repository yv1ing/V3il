package control

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const (
	websocketOpcodeContinuation = 0x0
	websocketOpcodeText         = 0x1
	websocketOpcodeBinary       = 0x2
	websocketOpcodeClose        = 0x8
	websocketOpcodePing         = 0x9
	websocketOpcodePong         = 0xa
	maxWebSocketMessageBytes    = 1024 * 1024
	websocketAcceptSuffix       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

type websocketReader struct {
	connection     net.Conn
	fragmentOpcode byte
	fragment       []byte
}

func validWebSocketUpgrade(request *http.Request) bool {
	return request.Method == http.MethodGet &&
		headerContainsToken(request.Header, "Connection", "upgrade") &&
		strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") &&
		strings.TrimSpace(request.Header.Get("Sec-WebSocket-Version")) == "13" &&
		validWebSocketKey(request.Header.Get("Sec-WebSocket-Key"))
}

func validWebSocketKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	return err == nil && len(decoded) == 16
}

func headerContainsToken(header http.Header, name string, expected string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), expected) {
				return true
			}
		}
	}
	return false
}

func websocketAccept(key string) string {
	digest := sha1.Sum([]byte(strings.TrimSpace(key) + websocketAcceptSuffix))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func newWebSocketReader(connection net.Conn) *websocketReader {
	return &websocketReader{connection: connection}
}

func (r *websocketReader) ReadMessage() ([]byte, byte, error) {
	for {
		payload, opcode, final, err := readWebSocketFrame(r.connection)
		if err != nil {
			return nil, 0, err
		}
		if opcode >= websocketOpcodeClose {
			return payload, opcode, nil
		}
		switch opcode {
		case websocketOpcodeContinuation:
			if r.fragmentOpcode == 0 {
				return nil, 0, errors.New("unexpected WebSocket continuation frame")
			}
			if len(r.fragment)+len(payload) > maxWebSocketMessageBytes {
				return nil, 0, errors.New("WebSocket message exceeds the size limit")
			}
			r.fragment = append(r.fragment, payload...)
			if final {
				message := r.fragment
				messageOpcode := r.fragmentOpcode
				r.fragment = nil
				r.fragmentOpcode = 0
				return message, messageOpcode, nil
			}
		case websocketOpcodeText, websocketOpcodeBinary:
			if r.fragmentOpcode != 0 {
				return nil, 0, errors.New("new WebSocket message started before fragmented message completed")
			}
			if final {
				return payload, opcode, nil
			}
			r.fragmentOpcode = opcode
			r.fragment = append(r.fragment[:0], payload...)
		default:
			return nil, 0, fmt.Errorf("unsupported WebSocket opcode 0x%x", opcode)
		}
	}
}

func readWebSocketFrame(connection net.Conn) ([]byte, byte, bool, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, 0, false, err
	}
	if header[0]&0x70 != 0 {
		return nil, 0, false, errors.New("WebSocket extensions are not supported")
	}
	final := header[0]&0x80 != 0
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	if !masked {
		return nil, 0, false, errors.New("client WebSocket frames must be masked")
	}

	payloadLength := uint64(header[1] & 0x7f)
	switch payloadLength {
	case 126:
		extended := make([]byte, 2)
		if _, err := io.ReadFull(connection, extended); err != nil {
			return nil, 0, false, err
		}
		payloadLength = uint64(binary.BigEndian.Uint16(extended))
		if payloadLength < 126 {
			return nil, 0, false, errors.New("non-canonical WebSocket payload length")
		}
	case 127:
		extended := make([]byte, 8)
		if _, err := io.ReadFull(connection, extended); err != nil {
			return nil, 0, false, err
		}
		payloadLength = binary.BigEndian.Uint64(extended)
		if payloadLength&(uint64(1)<<63) != 0 {
			return nil, 0, false, errors.New("invalid WebSocket payload length")
		}
		if payloadLength <= 65535 {
			return nil, 0, false, errors.New("non-canonical WebSocket payload length")
		}
	}
	if opcode >= websocketOpcodeClose && (!final || payloadLength > 125) {
		return nil, 0, false, errors.New("invalid WebSocket control frame")
	}
	if payloadLength > maxWebSocketMessageBytes {
		return nil, 0, false, errors.New("WebSocket frame exceeds the size limit")
	}

	mask := make([]byte, 4)
	if _, err := io.ReadFull(connection, mask); err != nil {
		return nil, 0, false, err
	}
	payload := make([]byte, int(payloadLength))
	if _, err := io.ReadFull(connection, payload); err != nil {
		return nil, 0, false, err
	}
	for index := range payload {
		payload[index] ^= mask[index%len(mask)]
	}
	return payload, opcode, final, nil
}

func writeWebSocketFrame(connection net.Conn, opcode byte, payload []byte) error {
	if len(payload) > maxWebSocketMessageBytes {
		return errors.New("WebSocket frame exceeds the size limit")
	}
	header := []byte{0x80 | opcode}
	switch length := len(payload); {
	case length < 126:
		header = append(header, byte(length))
	case length <= 65535:
		header = append(header, 126, byte(length>>8), byte(length))
	default:
		header = append(header, 127, 0, 0, 0, 0, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	}
	if err := writeWebSocketBytes(connection, header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	return writeWebSocketBytes(connection, payload)
}

func writeWebSocketBytes(connection net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := connection.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		payload = payload[written:]
	}
	return nil
}
