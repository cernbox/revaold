package storage_eos

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"
)

var ruid uint = 95491
var rgid uint = 2763

func TestEosFileInfoByPath(t *testing.T) {
	i := &instance{mgmURL: "root://eosbackup.cern.ch"}
	fi, err := i.eosFileInfoByPath(ruid, rgid, "/eos/scratch/user/g/gonzalhu/jeronimo")
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	fmt.Printf("%+v\n", fi)
}

func TestEosFind(t *testing.T) {
	i := instance{mgmURL: "root://eosbackup.cern.ch"}
	finfos, err := i.eosFind(ruid, rgid, "/eos/scratch/user/g/gonzalhu/jeronimo")
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	fmt.Printf("%+v\n", finfos)
}

func TestEosRead(t *testing.T) {
	i := instance{mgmURL: "root://eosbackup.cern.ch", cacheDirectory: "/tmp"}
	stream, err := i.eosRead(ruid, rgid, "/eos/scratch/user/g/gonzalhu/jeronimo/test1.txt")
	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}
	data, err := ioutil.ReadAll(stream)
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	fmt.Println(string(data))
}

func TestEosWrite(t *testing.T) {
	i := instance{mgmURL: "root://eosbackup.cern.ch", cacheDirectory: "/tmp"}
	b := ioutil.NopCloser(bytes.NewBufferString("hello world!"))
	err := i.eosWrite(ruid, rgid, "/eos/scratch/user/g/gonzalhu/jeronimo/hello_world.txt", b)
	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}
}

func TestEosListDeletedEntries(t *testing.T) {
	i := instance{mgmURL: "root://eosbackup.cern.ch", cacheDirectory: "/tmp"}
	entries, err := i.eosListDeletedEntries(ruid, rgid)
	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}
	for _, e := range entries {
		fmt.Println(e)
	}
}

func TestEosListVersions(t *testing.T) {
	i := instance{mgmURL: "root://eosbackup.cern.ch", cacheDirectory: "/tmp"}
	entries, err := i.eosListVersionsForFile(ruid, rgid, "/eos/scratch/user/g/gonzalhu/jeronimo/hello_world.txt")
	if err != nil {
		fmt.Println(err)
		t.Fail()
		return
	}
	for _, e := range entries {
		fmt.Println(e.File)
	}

}
