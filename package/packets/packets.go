package packets

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Comcast/gots/packet"
	"io"
	"log"
	"os"
)

const (
	packetSize = 188
	SyncByte   = 71 // 0x47 (0100 0111)
)

type header struct {
	//syncByte byte
	//transportErrorIndicator
	//payloadIndicator
	//transportPriority
	//PID
}

func DoStuff() {
	file, err := os.Open("internal/22391743-8603632-1113900.ts")
	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Cannot close File: %v \n%v", file.Name(), err)
		}
	}(file)
	readFile(file)
}

func readFile(file *os.File) {
	reader := bufio.NewReader(file)
	_, err := Sync(reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	pat, err := ReadPAT(reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err == nil {
		printPat(pat)
	}
	var paket [packetSize]byte
	var numPackets uint64
	var ccErrors uint64
	for {
		if _, err := io.ReadFull(reader, paket[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			fmt.Println(err)
			return
		}
		numPackets++
	}
	pkt := make([]byte, packetSize)
	//todo Ничего не пропустил?
	for read, err := file.Read(pkt); read > 0 && err == nil; read, err = file.Read(pkt) {
		if err != nil {
			println(err)
			return
		}

		pid := findPid(pkt)
		//canread := 0
		if pid == 0 {
			//log.Printf("packet %v is PMT", pkt)
			//canread++
		}
		//if canread > 1
		if pid != 0 {
			containsPayload := ContainsPayload(pkt)
			if containsPayload {
				cc := ContinuityCounter(pkt)
				//head := Header(pkt)

				//log.Printf("By header %v \nfound cc: %v", head, cc)
				//log.Printf("found cc", cc)
				if cc == 0 {
					//log.Printf("Found CCError at pkt: %v", pkt)
					ccErrors++
				}
			}
			//todo ничего не пропустил?
		}
		//log.Printf("%v, help me god", pid)
		if err != nil {
			log.Printf("%v", err)
		}
	}
	log.Printf("Total number of packets is: %v", numPackets)
	log.Printf("Total number of CCerrors is: %v", ccErrors)
}

func findPid(packet []byte) int {
	return int(packet[1]&0x1f)<<8 | int(packet[2])
}

func ContinuityCounter(packet []byte) uint8 {
	return packet[3] & uint8(0x0f)
}

func Header(packet []byte) []byte {
	start := payloadStart(packet)
	return packet[:start]
}

func payloadStart(packet []byte) int {
	var dataOffset = int(4) // packet header bytes
	if ContainsAdaptationField(packet) {
		afLength := int(packet[4])
		dataOffset += 1 + afLength
	}

	return dataOffset
}
func ContainsAdaptationField(packet []byte) bool {
	return packet[3]&0x20 != 0
}

func Payload(packet []byte) ([]byte, error) {
	if !ContainsPayload(packet) {
		return nil, errors.New("packet has no payload")
	}
	start := payloadStart(packet)
	if start > len(packet) {
		return nil, errors.New("invalid packet length")
	}
	pay := packet[start:]
	return pay, nil
}

func ContainsPayload(packet []byte) bool {
	return packet[3]&0x10 != 0
}

// Peeker wraps the Peek method.
type Peeker interface {
	// Peek returns the next n bytes without advancing the reader.
	Peek(n int) ([]byte, error)
}

// PeekScanner is an extended io.ByteScanner with peek capacity.
type PeekScanner interface {
	io.ByteScanner
	Peeker
}

// Sync uses IsSynced to determine whether a position is at packet header.
func Sync(r PeekScanner) (off int64, err error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return off, errors.New("sync byte not found")
			}
			return off, err
		}
		if b != SyncByte {
			off++
			continue
		}

		err = r.UnreadByte()
		if err != nil {
			return off, err
		}
		ok, err := IsSynced(r)
		if ok {
			return off, nil
		}
		if err != nil {
			if err == io.EOF {
				return off, errors.New("sync byte not found")
			}
			return off, err
		}

		// Advance again. This is a consequence of not
		// duplicating IsSynced for 3 and 4 byte reads.
		_, err = r.ReadByte()
		// These errors should never happen since we
		// have already read this byte above.
		if err != nil {
			if err == io.EOF {
				return off, errors.New("sync byte not found")
			}
			return off, err
		}
	}
}

func IsSynced(r Peeker) (ok bool, err error) {
	b, err := r.Peek(4)
	if err != nil {
		return false, err
	}
	// Check that the first byte is the sync byte.
	if b[0] != SyncByte {
		return false, nil
	}

	const (
		pidMask = 0x1fff << 8
		afcMask = 0x3 << 4
	)
	header := binary.BigEndian.Uint32(b)

	// Check that the AFC is not zero (reserved).
	afc := header & afcMask
	if afc == 0x0 {
		return false, nil
	}

	// Check that the PID is not 0x4-0xf (reserved).
	pid := (header & pidMask) >> 8
	return pid < 0x4 || 0xf < pid, nil
}

func ReadPAT(r io.Reader) (PAT, error) {
	var pkt packet.Packet
	var pat PAT
	for pat == nil {
		if _, err := io.ReadFull(r, pkt[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, err
		}
		isPat := packet.IsPat(&pkt)

		if isPat {
			pay, err := packet.Payload(&pkt)
			if err != nil {
				return nil, err
			}
			cp := make([]byte, len(pay))
			copy(cp, pay)
			pat, err := NewPAT(cp)
			if err != nil {
				return nil, err
			}
			return pat, nil
		}
	}
	return nil, errors.New("pat not found")
}
func IsPat(packet []byte) bool {
	return findPid(packet) == 0
}

// PAT interface represents operations on a Program Association Table. Currently only single program transport streams (SPTS)are supported
type PAT interface {
	NumPrograms() int
	ProgramMap() map[int]int
	SPTSpmtPID() (int, error)
}

type pat []byte

func NewPAT(patBytes []byte) (PAT, error) {
	if len(patBytes) < 13 {
		return nil, errors.New("invalid pat length")
	}

	if len(patBytes) == 188 {
		var pkt packet.Packet
		copy(pkt[:], patBytes)
		var err error
		patBytes, err = packet.Payload(&pkt)
		if err != nil {
			return nil, err
		}
	}

	return pat(patBytes), nil
}

func (pat pat) ProgramMap() map[int]int {
	m := make(map[int]int)

	counter := 8 // skip table id et al

	for i := 0; i < pat.NumPrograms(); i++ {
		pn := (int(pat[counter+1]) << 8) | int(pat[counter+2])

		// ignore the top three (reserved) bits
		pid := int(pat[counter+3])&0x1f<<8 | int(pat[counter+4])

		// A value of 0 is reserved for a NIT packet identifier.
		if pn > 0 {
			m[pn] = pid
		}

		counter += 4
	}

	return m
}

// SPTSpmtPID returns the PMT PID if and only if this pat is for a single program transport stream. If this pat is for a multiprogram transport stream, an error is returned.
func (pat pat) SPTSpmtPID() (int, error) {
	if pat.NumPrograms() > 1 {
		return 0, errors.New("Not a single program transport stream")
	}
	for _, pid := range pat.ProgramMap() {
		return pid, nil
	}
	return 0, errors.New("No programs in transport stream")
}

// NumPrograms returns the number of programs in this PAT
func (pat pat) NumPrograms() int {
	sectionLength := int(SectionLength(pat))
	if len(pat[:]) < sectionLength {
		sectionLength = len(pat[:])
	}
	numPrograms := int((sectionLength -
		2 - // Transport Stream ID
		1 - // Reserved|VersionNumber|CurrentNextIndicator
		1 - // Section Number
		1 - // Last Section Number
		4) / // CRC32
		4) // Divided by 4 bytes per program
	return numPrograms
}

func SectionLength(psi []byte) uint16 {
	offset := int(1 + PointerField(psi))
	if offset >= len(psi) {
		return 0
	}
	return sectionLength(psi[offset:])
}

func PointerField(psi []byte) uint8 {
	return psi[0]
}

// sectionLength returns the length of a single psi section
func sectionLength(psi []byte) uint16 {
	return uint16(psi[1]&3)<<8 | uint16(psi[2])
}

func printPat(pat PAT) {
	fmt.Println("Pat")
	fmt.Printf("\tPMT PIDs %v\n", pat.ProgramMap())
	fmt.Printf("\tNumber of Programs %v\n", pat.NumPrograms())
}
