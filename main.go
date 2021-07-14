/*
  Program created for monitoring windows process.
  This have to make simple researching malware analyse.
*/
package main

import (
	"fmt"
	wmi "github.com/StackExchange/wmi"
	"time"
)

//const (
//	Delete = -1
//	Adding = 1
//	Nothing = 0
//)

type Win32_Process struct {
	Name string
	//ProcessName       string
	//ExecutablePath    string
	ProcessId int
	//ParentProcessId   string
	//VirtualSize       string
	//InstallDate       string
	//CreationClassName string
	CreationDate string
}

var beginProcesses  []Win32_Process
var endingProcesses []Win32_Process

func processesHunt(q string, oldProc, newProc []Win32_Process) {
	for ; ; {
		err := wmi.Query(q, &oldProc)
		if err != nil {
			fmt.Println(err)
		}
		time.Sleep(3 * time.Second)
		err = wmi.Query(q, &newProc)
		if err != nil {
			fmt.Println(err)
		}

		for _, row := range newProc {
			if !containRow(oldProc, row.CreationDate) {
				fmt.Printf("[CREATED] [%d] %s, create time: %s\n", row.ProcessId, row.Name, row.CreationDate)
			}
		}
		for _, row := range oldProc {
			if !containRow(newProc, row.CreationDate) {
				fmt.Printf("[DELETED] [%d] %s, was created: %s\n", row.ProcessId, row.Name, row.CreationDate)
			}
		}
		oldProc = newProc
	}
}

func containRow(list []Win32_Process, find string) bool {
	for _, w := range list {
		if w.CreationDate == find {
			return true
		}
	}
	return false
}


func main() {
	//var dst []Win32_Process
	var oldProcesses []Win32_Process
	var newProcesses []Win32_Process
	q := wmi.CreateQuery(&oldProcesses, "")
	err := wmi.Query(q, &beginProcesses)
	if err != nil {
		fmt.Println(err)
	}
	go processesHunt(q, oldProcesses, newProcesses)
	//go fileMonitor()
	var input string
	_, err = fmt.Scanln(&input)
	if err != nil {
		err = wmi.Query(q, &endingProcesses)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("==================================================================")
		fmt.Println("=================SUMMARY PROCESS CHANGES==========================")
		fmt.Println("==================================================================")
		for _, row := range endingProcesses {
			if !containRow(beginProcesses, row.CreationDate) {
				fmt.Printf("[CREATED] [%d] %s, create time: %s\n", row.ProcessId, row.Name, row.CreationDate)
			}
		}
		for _, row := range beginProcesses {
			if !containRow(endingProcesses, row.CreationDate) {
				fmt.Printf("[DELETED] [%d] %s, was created: %s\n", row.ProcessId, row.Name, row.CreationDate)
			}
		}
	}
}
