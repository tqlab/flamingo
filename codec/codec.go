package codec

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"github.com/golang/protobuf/proto"
	"github.com/tqlab/flamingo/core"
	"io"
)

type Codec interface {
	Encode(message []byte) ([]byte, error)

	Decode(reader *bufio.Reader)

	ReadMessage(logger *core.ColorLogger, reader io.Reader, msg proto.Message) (int32, error)
}

type SimpleCodec struct {
}

func NewCodec() *SimpleCodec {
	return &SimpleCodec{}
}

func (sm *SimpleCodec) Encode(message []byte) ([]byte, error) {
	// 读取消息的长度
	var length = len(message)
	var pkg = new(bytes.Buffer)
	// 写入消息头
	err := binary.Write(pkg, binary.LittleEndian, int32(length))
	if err != nil {
		return nil, err
	}
	// 写入消息实体
	err = binary.Write(pkg, binary.LittleEndian, message)
	if err != nil {
		return nil, err
	}

	return pkg.Bytes(), nil
}

func (sm *SimpleCodec) Decode(reader io.Reader) ([]byte, error) {

	lengthBuf := make([]byte, 4)
	_, err := io.ReadFull(reader, lengthBuf)
	if err != nil {
		return nil, err
	}
	//check error
	length := binary.LittleEndian.Uint32(lengthBuf)

	pack := make([]byte, length)
	_, err = io.ReadFull(reader, pack)
	if err != nil {
		return nil, err
	}
	return pack, nil
}

func (sm *SimpleCodec) ReadMessage(reader io.Reader, msg proto.Message) (int32, error) {
	data, err := sm.Decode(reader)
	if err != nil {
		return 0, err
	}

	length := len(data) + 4
	err = proto.Unmarshal(data, msg)
	if err != nil {
		return 0, err
	}
	return int32(length), nil
}
