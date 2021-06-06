package securitycdn

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"
)


func TestName(t *testing.T) {
	testFile := "test.data"
	appendFile := "append.data"
	dfile := "decode.data"
	os.Remove(appendFile)

	key := "6368616e676520746869732070617373776f726420746f206120736563726574"
	d := driver{}

	fp, err := os.OpenFile(appendFile, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = fp.Truncate(0)
	if err != nil {
		fp.Close()
		fmt.Println(err)
		return
	}

	data, err := ioutil.ReadFile(testFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	nonce := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Printf("init nonce err: %v", err)
		return
	}
	writer := bufio.NewWriter(fp)
	err = d.encrypt(writer, bytes.NewBuffer([]byte(data)), key, nonce)
	if err !=nil {
		fmt.Println(err)
		return
	}
	if err := writer.Flush(); err != nil {
		fmt.Println(err)
	}

	//解密
	encodeData, _ := ioutil.ReadFile(appendFile)
	dp, _ := os.OpenFile(dfile, os.O_WRONLY|os.O_CREATE, 0666)
	writer = bufio.NewWriter(dp)
	err = d.encrypt(writer, bytes.NewBuffer([]byte(encodeData)), key, nonce)
	if err !=nil {
		fmt.Println(err)
		return
	}
	writer.Flush()

	return
}