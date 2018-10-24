package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	direct  bool
	timeout = time.Second * 10
)

func httpStart(local_vm string, remote_vm string) {
	direct = false // 不直接连接

	l, err := net.Listen("tcp", local_vm)
	if err != nil {
		log.Fatalf("监听失败:%s", err)
	}
	log.Printf("http or https :%s ,socks5 :%s  ", local_vm, remote_vm)
	for {
		client, err := l.Accept()
		checkErr(err)
		go handle(client, remote_vm)
	}
}

func checkErr(err error) {
	if err != nil {
		_, file, line, ok := runtime.Caller(1)
		if ok {
			panic(fmt.Errorf("%s:%d: %s", filepath.Base(file), line, err))
		}
		panic(err)
	}
}

func handle(client net.Conn, remote_vm string) {
	if client == nil {
		return
	}
	defer client.Close()

	var b [1024]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}
	var method, host, address string
	fmt.Sscanf(string(b[:bytes.IndexByte(b[:], '\n')]), "%s%s", &method, &host)
	hostPortURL, err := url.Parse(host)
	if err != nil {
		log.Println(err)
		return
	}

	if hostPortURL.Opaque == "443" { //https访问
		address = hostPortURL.Scheme + ":443"
	} else { //http访问
		if strings.Index(hostPortURL.Host, ":") == -1 { //host不带端口， 默认80
			address = hostPortURL.Host + ":80"
		} else {
			address = hostPortURL.Host
		}
	}

	//获得了请求的host和port，就开始拨号吧
	server, err := socks5(address, remote_vm)
	if err != nil {
		log.Println(err)
		return
	}
	if method == "CONNECT" {
		fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else {
		server.Write(b[:n])
	}
	//进行转发
	go io.Copy(server, client)
	io.Copy(client, server)
}

// 通过socks5转发
func socks5(host string, remote_vm string) (Conn net.Conn, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("socks5 proxy error:%s", e)
			if Conn != nil {
				Conn.Close()
				Conn = nil
			}
		}
	}()
	var (
		addr, port string
	)
	addr, port, err = net.SplitHostPort(host)
	checkErr(err)
	Conn, err = net.DialTimeout("tcp", remote_vm, timeout)
	checkErr(err)

	Conn.Write([]byte{0x05, 01, 00})
	var raw [1024]byte
	n, err := Conn.Read(raw[:])
	checkErr(err)
	if binary.BigEndian.Uint16(raw[:2]) != 0x0500 {
		panic(errors.New("不支持该代理服务器！"))
	}

	// 将端口转为两个字节 二进制表示

	p := make([]byte, 2, 2)
	i, err := strconv.Atoi(port)
	binary.BigEndian.PutUint16(p, uint16(i))

	if i := net.ParseIP(addr); i != nil {
		// TODO : 添加IPv6支持
		// IP地址
		if ipv4 := i.To4(); ipv4 != nil {
			_, err = Conn.Write(append(append([]byte{0x05, 0x01, 0x00, 0x01}, []byte(ipv4)...), p...))
			checkErr(err)
		} else if ipv6 := i.To16(); ipv6 != nil {
			_, err = Conn.Write(append(append([]byte{0x05, 0x01, 0x00, 0x04}, []byte(ipv4)...), p...))
			checkErr(err)
		} else {
			panic(errors.New("未知错误！"))
		}
	} else {
		// 域名 ATYP =  0x03
		copy(raw[0:4], []byte{0x05, 0x01, 0x00, 0x03})
		length := len([]byte(addr))
		if length > 0xff {
			panic(errors.New("目标地址超过最大长度！"))
		}
		raw[4] = byte(length)
		copy(raw[5:7+length], append([]byte(addr), p...))
		_, err = Conn.Write(raw[:7+length])
		checkErr(err)
	}

	n, err = Conn.Read(raw[:])
	if err == io.EOF {
		panic(errors.New("远程服务器断开链接！"))
	}
	checkErr(err)

	if raw[0] != 0x05 || raw[2] != 0x00 {
		panic(errors.New("不支持代理服务器！"))
	}

	switch raw[1] {
	case 0x00:
		break
	case 0x01:
		panic(errors.New("服务器错误:X'01' general SOCKS server failure"))
	case 0x02:
		panic(errors.New("服务器错误:X'02' connection not allowed by ruleset"))
	case 0x03:
		panic(errors.New("服务器错误:X'03' Network unreachable"))
	case 0x04:
		panic(errors.New("服务器错误:X'04' Host unreachable"))
	case 0x05:
		panic(errors.New("服务器错误:X'05' Connection refused"))
	case 0x06:
		panic(errors.New("服务器错误:X'06' TTL expired"))
	case 0x07:
		panic(errors.New("服务器错误:X'07' Command not supported"))
	case 0x08:
		panic(errors.New("服务器错误:X'08' Address type not supported"))
	case 0x09:
		panic(errors.New("服务器错误:X'09' to X'FF' unassigned"))
	}
	switch raw[3] {
	case 0x01:
		BindHost := net.IPv4(raw[4], raw[5], raw[6], raw[7]).String()
		BindPort := strconv.Itoa(int(raw[n-2])<<8 | int(raw[n-1]))
		log.Printf("%s <-> %s <-> %s <-> %s", Conn.LocalAddr().String(), Conn.RemoteAddr().String(), net.JoinHostPort(BindHost, BindPort), host)
	case 0x03:
		// TODO： 绑定的是域名
	case 0x04:
		// TODO： 绑定的是IPv6地址
	default:
		// TODO： 未知类型
		panic(errors.New("未知代理类型"))
	}

	return Conn, nil
}

func address(host string) string {
	var address string
	if strings.Index(host, "://") != -1 {
		uinfo, err := url.Parse(host)
		checkErr(err)
		address = uinfo.Host
	} else {
		address = host
	}

	if strings.IndexByte(address, ':') == -1 {
		address = net.JoinHostPort(address, "80")
	}
	return address
}