// ============================================================================
// DCF - Data Cryptography File Tool (V Port)
// V utility for encrypted archive creation and extraction
//
// Copyright (c) 2026 Dario Deledda. All rights reserved.
// Use of this source code is governed by an MPL 2.0 license
// that can be found in the LICENSE file.
// 
// Usage:
//   Compile: v -prod crypto.v
//   Encrypt: ./dcf <file(s) or folder> [-o output.dcf] [-p key]
//   Decrypt: ./dcf <archive.dcf> [-p key]
// ============================================================================

import os
import time
import term
import strings
import crypto.sha256
import encoding.binary

const default_key = 'mysecretkey'
const magic = [u8(`D`), `C`, `F`, `1`]
const version = u32(4)
const chunk_size = 4 * 1024 * 1024
const tag_size = 16

// ============================================================================
// CRC32 IMPLEMENTATION
// ============================================================================
const crc32_table = build_crc32_table()

fn build_crc32_table() []u32 {
	mut table := []u32{len: 256}
	for i in 0 .. 256 {
		mut c := u32(i)
		for _ in 0 .. 8 {
			if (c & 1) != 0 {
				c = u32(0xEDB88320) ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	return table
}

struct CRC32 {
mut:
	crc u32 = 0xFFFFFFFF
}

fn (mut c CRC32) update(data []u8) {
	for b in data {
		c.crc = crc32_table[(c.crc ^ u32(b)) & u32(0xFF)] ^ (c.crc >> 8)
	}
}

fn (c &CRC32) finalize() u32 {
	return c.crc ^ 0xFFFFFFFF
}

fn crc32_calc(data []u8) u32 {
	mut crc := CRC32{}
	crc.update(data)
	return crc.finalize()
}

// ============================================================================
// PROGRESS BAR UTILITY
// ============================================================================
struct ProgressBar {
mut:
	label       string
	total       u64
	current     u64
	status      string
	finished    bool
	enabled     bool
	start_time  time.Time
	last_update f64
}

fn new_progress_bar(label string, total_bytes u64) ProgressBar {
	return ProgressBar{
		label:       label
		total:       total_bytes
		current:     0
		enabled:     true
		start_time:  time.now()
		last_update: 0.0
	}
}

fn (mut p ProgressBar) update(current u64, status string) {
	p.current = current
	if status != '' {
		p.status = status
	}

	elapsed := time.since(p.start_time).seconds()
	if elapsed - p.last_update < 0.1 && p.current < p.total {
		return
	}
	p.last_update = elapsed

	if !p.enabled || p.finished {
		return
	}
	p.render(elapsed)
}

fn (mut p ProgressBar) set_total(new_total u64) {
	p.total = new_total
}

fn (mut p ProgressBar) set_status(status string) {
	p.status = status
	p.update(p.current, '')
}

fn (mut p ProgressBar) finish() {
	p.finished = true
	if !p.enabled {
		return
	}
	p.render(time.since(p.start_time).seconds())
	println('')
}

fn (p &ProgressBar) render(elapsed f64) {
	mut term_width, _ := term.get_terminal_size()
	if term_width < 30 {
		term_width = 80
	}

	width := 20
	mut progress := if p.total > 0 { f64(p.current) / f64(p.total) } else { 0.0 }
	if progress > 1.0 { progress = 1.0 }

	filled := int(progress * width)
	bar := '[' + strings.repeat(`#`, filled) + strings.repeat(`-`, width - filled) + ']'

	speed_val := if elapsed > 0 { f64(p.current) / elapsed } else { 0.0 }
	speed := format_bytes(u64(speed_val)) + '/s'
	pct_str := '${int(progress * 100)}%'

	mut time_eta := '--:--'
	if p.current > 0 && p.total > 0 && p.current < p.total && elapsed > 0 {
		current_speed := f64(p.current) / elapsed
		remaining_bytes := f64(p.total - p.current)
		eta_seconds := remaining_bytes / current_speed
		time_eta = format_time(eta_seconds)
	} else if p.current >= p.total && p.total > 0 {
		time_eta = '00:00'
	}

	mut out_str := '${p.label} ${bar} ${format_bytes(p.current)}/${format_bytes(p.total)} ${pct_str} ${speed} ETA: ${time_eta}'
	if p.status != '' {
		out_str += ' [${p.status}]'
	}

	if out_str.len >= term_width {
		out_str = out_str[0..term_width - 1]
	}

	print('\r\x1b[K' + out_str)
	os.flush()
}

fn format_bytes(bytes u64) string {
	b := f64(bytes)
	if b >= 1073741824.0 { return '${b / 1073741824.0:.1f}GB' }
	if b >= 1048576.0 { return '${b / 1048576.0:.1f}MB' }
	if b >= 1024.0 { return '${b / 1024.0:.1f}KB' }
	return '${bytes}B'
}

fn format_time(seconds f64) string {
	s := int(seconds)
	h := s / 3600
	m := (s % 3600) / 60
	sec := s % 60
	if h > 0 { return '${h:02d}:${m:02d}:${sec:02d}' }
	return '${m:02d}:${sec:02d}'
}

// ============================================================================
// CHACHA20-POLY1305 AEAD CHUNKED ENCRYPTION
// ============================================================================
@[inline]
fn chacha_quarter_round(mut s []u32, a int, b int, c int, d int) {
	s[a] += s[b] s[d] ^= s[a] s[d] = (s[d] << 16) | (s[d] >> 16)
	s[c] += s[d] s[b] ^= s[c] s[b] = (s[b] << 12) | (s[b] >> 20)
	s[a] += s[b] s[d] ^= s[a] s[d] = (s[d] << 8)  | (s[d] >> 24)
	s[c] += s[d] s[b] ^= s[c] s[b] = (s[b] << 7)  | (s[b] >> 25)
}

fn chacha_block(input []u32, mut output []u32) {
	mut x := []u32{len: 16}
	for i in 0 .. 16 { x[i] = input[i] }
	for round := 0; round < 20; round += 2 {
		chacha_quarter_round(mut x, 0, 4, 8, 12)
		chacha_quarter_round(mut x, 1, 5, 9, 13)
		chacha_quarter_round(mut x, 2, 6, 10, 14)
		chacha_quarter_round(mut x, 3, 7, 11, 15)
		chacha_quarter_round(mut x, 0, 5, 10, 15)
		chacha_quarter_round(mut x, 1, 6, 11, 12)
		chacha_quarter_round(mut x, 2, 7, 8, 13)
		chacha_quarter_round(mut x, 3, 4, 9, 14)
	}
	for i in 0 .. 16 { output[i] = x[i] + input[i] }
}

fn chacha_encrypt(in_data []u8, len int, key []u8, counter u32, nonce u64, mut out_data []u8) {
	mut state := []u32{len: 16}
	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574
	for i in 0 .. 8 {
		state[4 + i] = 0
		for j in 0 .. 4 {
			state[4 + i] |= u32(key[i * 4 + j]) << (j * 8)
		}
	}
	state[12] = counter
	state[13] = u32(nonce & 0xFFFFFFFF)
	state[14] = u32(nonce >> 32)
	state[15] = 0

	mut offset := 0
	mut keystream := []u32{len: 16}

	for offset < len {
		chacha_block(state, mut keystream)
		remaining := len - offset
		mut to_process := 64
		if remaining < 64 { to_process = remaining }

		for i := 0; i < to_process; i++ {
			k_byte := u8((keystream[i / 4] >> ((i % 4) * 8)) & 0xFF)
			out_data[offset + i] = in_data[offset + i] ^ k_byte
		}
		offset += to_process
		state[12]++
	}
}

fn poly1305_mac(msg []u8, msg_len int, key []u8, mut tag []u8) {
	t0 := u32(key[0]) | (u32(key[1]) << 8) | (u32(key[2]) << 16) | (u32(key[3]) << 24)
	t1 := u32(key[4]) | (u32(key[5]) << 8) | (u32(key[6]) << 16) | (u32(key[7]) << 24)
	t2 := u32(key[8]) | (u32(key[9]) << 8) | (u32(key[10]) << 16) | (u32(key[11]) << 24)
	t3 := u32(key[12]) | (u32(key[13]) << 8) | (u32(key[14]) << 16) | (u32(key[15]) << 24)

	r0 := u64(t0 & 0x3FFFFFF)
	r1 := u64(((t0 >> 26) | (t1 << 6)) & 0x3FFFF03)
	r2 := u64(((t1 >> 20) | (t2 << 12)) & 0x3FFC0FF)
	r3 := u64(((t2 >> 14) | (t3 << 18)) & 0x3F03FFF)
	r4 := u64((t3 >> 8) & 0x00FFFFF)

	mut h0, mut h1, mut h2, mut h3, mut h4 := u64(0), u64(0), u64(0), u64(0), u64(0)
	mut pos := 0

	for pos < msg_len {
		mut n := 16
		if msg_len - pos < 16 { n = msg_len - pos }
		mut block := []u8{len: 17, init: 0}
		copy(mut block[0..n], msg[pos..pos + n])
		block[n] = 1

		c0 := (u64(block[0]) | (u64(block[1]) << 8) | (u64(block[2]) << 16) | (u64(block[3]) << 24)) & 0x3FFFFFF
		c1 := ((u64(block[3]) >> 2) | (u64(block[4]) << 6) | (u64(block[5]) << 14) | (u64(block[6]) << 22)) & 0x3FFFFFF
		c2 := ((u64(block[6]) >> 4) | (u64(block[7]) << 4) | (u64(block[8]) << 12) | (u64(block[9]) << 20)) & 0x3FFFFFF
		c3 := ((u64(block[9]) >> 6) | (u64(block[10]) << 2) | (u64(block[11]) << 10) | (u64(block[12]) << 18)) & 0x3FFFFFF
		c4 := (u64(block[13]) | (u64(block[14]) << 8) | (u64(block[15]) << 16) | (u64(block[16]) << 24))

		h0 += c0; h1 += c1; h2 += c2; h3 += c3; h4 += c4

		d0 := h0 * r0 + h1 * r4 * 5 + h2 * r3 * 5 + h3 * r2 * 5 + h4 * r1 * 5
		d1 := h0 * r1 + h1 * r0     + h2 * r4 * 5 + h3 * r3 * 5 + h4 * r2 * 5
		d2 := h0 * r2 + h1 * r1     + h2 * r0     + h3 * r4 * 5 + h4 * r3 * 5
		d3 := h0 * r3 + h1 * r2     + h2 * r1     + h3 * r0     + h4 * r4 * 5
		d4 := h0 * r4 + h1 * r3     + h2 * r2     + h3 * r1     + h4 * r0

		mut c_val := d0 >> 26; h0 = d0 & 0x3FFFFFF; mut d1_v := d1 + c_val
		c_val = d1_v >> 26; h1 = d1_v & 0x3FFFFFF; mut d2_v := d2 + c_val
		c_val = d2_v >> 26; h2 = d2_v & 0x3FFFFFF; mut d3_v := d3 + c_val
		c_val = d3_v >> 26; h3 = d3_v & 0x3FFFFFF; mut d4_v := d4 + c_val
		c_val = d4_v >> 26; h4 = d4_v & 0x3FFFFFF; h0 += c_val * 5
		c_val = h0 >> 26; h0 = h0 & 0x3FFFFFF; h1 += c_val
		pos += 16
	}

	mut c_val := h1 >> 26; h1 &= 0x3FFFFFF; h2 += c_val
	c_val = h2 >> 26; h2 &= 0x3FFFFFF; h3 += c_val
	c_val = h3 >> 26; h3 &= 0x3FFFFFF; h4 += c_val
	c_val = h4 >> 26; h4 &= 0x3FFFFFF; h0 += c_val * 5
	c_val = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c_val

	g0 := h0 + 5; c_val = g0 >> 26; g0_final := g0 & 0x3FFFFFF
	g1 := h1 + c_val; c_val = g1 >> 26; g1_final := g1 & 0x3FFFFFF
	g2 := h2 + c_val; c_val = g2 >> 26; g2_final := g2 & 0x3FFFFFF
	g3 := h3 + c_val; c_val = g3 >> 26; g3_final := g3 & 0x3FFFFFF
	g4 := h4 + c_val - (u64(1) << 26)

	if (g4 & (u64(1) << 63)) == 0 {
		h0 = g0_final; h1 = g1_final; h2 = g2_final; h3 = g3_final; h4 = g4
	}

	mac0 := h0 | (h1 << 26) | (h2 << 52)
	mac1 := (h2 >> 12) | (h3 << 14) | (h4 << 40)

	mut s0, mut s1 := u64(0), u64(0)
	for i in 0 .. 8 {
		s0 |= (u64(key[16 + i]) << (i * 8))
		s1 |= (u64(key[24 + i]) << (i * 8))
	}

	out0 := mac0 + s0
	mut out1 := mac1 + s1
	if out0 < mac0 { out1++ }

	for i in 0 .. 8 {
		tag[i] = u8((out0 >> (i * 8)) & 0xFF)
		tag[i + 8] = u8((out1 >> (i * 8)) & 0xFF)
	}
}

fn derive_key_and_nonce(key string, chunk_index u64, mut out_key []u8, mut out_nonce []u64) {
	mut input := []u8{}
	input << key.bytes()
	for i in 0 .. 8 {
		input << u8((chunk_index >> (i * 8)) & 0xFF)
	}
	input << 0 // Suffix '0' for Key
	key_hash := sha256.sum256(input)
	copy(mut out_key[0..32], key_hash)

	input[input.len - 1] = 1 // Suffix '1' for Nonce
	nonce_hash := sha256.sum256(input)
	
	mut nonce := u64(0)
	for i in 0 .. 8 {
		nonce |= u64(nonce_hash[i]) << (i * 8)
	}
	out_nonce[0] = nonce
}

fn chacha_encrypt_chunk(in_data []u8, len int, key string, chunk_index u64, mut out_data []u8) {
	mut chunk_key := []u8{len: 32}
	mut nonce_arr := []u64{len: 1}
	derive_key_and_nonce(key, chunk_index, mut chunk_key, mut nonce_arr)
	nonce := nonce_arr[0]

	mut poly_state := []u32{len: 16}
	poly_state[0] = 0x61707865
	poly_state[1] = 0x3320646e
	poly_state[2] = 0x79622d32
	poly_state[3] = 0x6b206574
	for i in 0 .. 8 {
		poly_state[4 + i] = 0
		for j in 0 .. 4 {
			poly_state[4 + i] |= u32(chunk_key[i * 4 + j]) << (j * 8)
		}
	}
	poly_state[12] = 0
	poly_state[13] = u32(nonce & 0xFFFFFFFF)
	poly_state[14] = u32(nonce >> 32)
	poly_state[15] = 0

	mut poly_keystream := []u32{len: 16}
	chacha_block(poly_state, mut poly_keystream)

	mut poly_key := []u8{len: 32}
	for i in 0 .. 32 {
		poly_key[i] = u8((poly_keystream[i / 4] >> ((i % 4) * 8)) & 0xFF)
	}

	chacha_encrypt(in_data, len, chunk_key, 1, nonce, mut out_data)
	
	mut tag := []u8{len: 16}
	poly1305_mac(out_data[0..len], len, poly_key, mut tag)
	copy(mut out_data[len..len + 16], tag)
}

// ============================================================================
// ARCHIVE CREATION
// ============================================================================
struct ArchiveEntry {
	relative_path string
	is_directory  bool
	source_path   string
	content_size  u64
}

fn collect_entries(base_path string, current_path string, mut entries []ArchiveEntry) {
	if os.is_dir(current_path) {
		mut rel_path := current_path
		if current_path.starts_with(base_path) {
			rel_path = current_path[base_path.len..]
			if rel_path.starts_with(os.path_separator) {
				rel_path = rel_path[1..]
			}
		}
		
		if rel_path != '' {
			entries << ArchiveEntry{
				relative_path: rel_path
				is_directory:  true
				source_path:   current_path
				content_size:  0
			}
		}
		
		files := os.ls(current_path) or { []string{} }
		for f in files {
			collect_entries(base_path, os.join_path(current_path, f), mut entries)
		}
	} else if os.is_file(current_path) {
		mut rel_path := current_path
		if current_path.starts_with(base_path) {
			rel_path = current_path[base_path.len..]
			if rel_path.starts_with(os.path_separator) {
				rel_path = rel_path[1..]
			}
		}
		size := os.file_size(current_path)
		entries << ArchiveEntry{
			relative_path: rel_path
			is_directory:  false
			source_path:   current_path
			content_size:  size
		}
	}
}

struct ArchiveWriter {
mut:
	out_file       os.File
	key            string
	push_buf       []u8
	push_offset    int
	file_offset    u64
	crc_obj        CRC32
	header_written bool
}

fn (mut w ArchiveWriter) flush_buf(mut bar ProgressBar) ! {
	if w.push_offset == 0 { return }
	
	crc_start := if w.header_written { 0 } else { 20 }
	if w.push_offset > crc_start {
		w.crc_obj.update(w.push_buf[crc_start..w.push_offset])
	}
	w.header_written = true
	
	chacha_encrypt_chunk(w.push_buf[0..w.push_offset], w.push_offset, w.key, w.file_offset / u64(chunk_size), mut w.push_buf)
	if w.file_offset == 0 { w.out_file.seek(20, .start)! }
	
	w.out_file.write(w.push_buf[0..w.push_offset + tag_size])!
	w.file_offset += u64(w.push_offset)
	w.push_offset = 0
	bar.update(w.file_offset, '')
}

fn (mut w ArchiveWriter) push_bytes(data []u8, mut bar ProgressBar) ! {
	mut remaining := data.len
	mut data_pos := 0
	for remaining > 0 {
		mut to_copy := remaining
		if chunk_size - w.push_offset < remaining {
			to_copy = chunk_size - w.push_offset
		}
		copy(mut w.push_buf[w.push_offset..w.push_offset + to_copy], data[data_pos..data_pos + to_copy])
		w.push_offset += to_copy
		data_pos += to_copy
		remaining -= to_copy
		
		if w.push_offset == chunk_size { w.flush_buf(mut bar)! }
	}
}

fn create_archive(paths []string, key string, output_path string, mut bar ProgressBar) ! {
	mut entries := []ArchiveEntry{}
	mut base_path := os.getwd()
	if paths.len == 1 && os.is_dir(paths[0]) {
		base_path = os.dir(paths[0])
	}
	if !base_path.ends_with(os.path_separator) {
		base_path += os.path_separator
	}
	
	for path in paths {
		collect_entries(base_path, path, mut entries)
	}

	bar.set_status('Calculating size...')
	mut total_size := u64(20) // Header
	for e in entries {
		total_size += 4 + u64(e.relative_path.len) + 1 + 8 + e.content_size
	}
	bar.set_total(total_size)

	mut out_file := os.create(output_path)!
	
	mut w := ArchiveWriter{
		out_file:       out_file
		key:            key
		push_buf:       []u8{len: chunk_size + tag_size, init: 0}
		push_offset:    20
		file_offset:    0
		crc_obj:        CRC32{}
		header_written: false
	}

	mut header_buf := []u8{len: 20}
	header_buf[0] = magic[0]; header_buf[1] = magic[1]; header_buf[2] = magic[2]; header_buf[3] = magic[3]
	binary.little_endian_put_u32(mut header_buf[4..8], version)
	binary.little_endian_put_u32(mut header_buf[8..12], u32(entries.len))
	copy(mut w.push_buf[0..20], header_buf)

	bar.set_status('Building archive...')
	mut path_len_buf := []u8{len: 4}
	mut size_buf := []u8{len: 8}

	for entry in entries {
		binary.little_endian_put_u32(mut path_len_buf, u32(entry.relative_path.len))
		w.push_bytes(path_len_buf, mut bar)!
		w.push_bytes(entry.relative_path.bytes(), mut bar)!
		
		is_dir_byte := if entry.is_directory { u8(1) } else { u8(0) }
		w.push_bytes([is_dir_byte], mut bar)!
		
		binary.little_endian_put_u64(mut size_buf, entry.content_size)
		w.push_bytes(size_buf, mut bar)!
		
		if !entry.is_directory && entry.content_size > 0 {
			mut file := os.open(entry.source_path)!
			mut remaining := entry.content_size
			mut file_buf := []u8{len: 65536}
			for remaining > 0 {
				mut to_read := file_buf.len
				if remaining < u64(file_buf.len) { to_read = int(remaining) }
				
				read_count := file.read(mut file_buf[0..to_read]) or { 0 }
				if read_count == 0 { break }
				
				w.push_bytes(file_buf[0..read_count], mut bar)!
				remaining -= u64(read_count)
			}
			file.close()
		}
	}
	w.flush_buf(mut bar)!

	mut final_header := []u8{len: 20}
	copy(mut final_header[0..12], header_buf[0..12])
	
	content_crc_val := w.crc_obj.finalize()
	binary.little_endian_put_u32(mut final_header[12..16], content_crc_val)
	header_crc_val := crc32_calc(final_header[0..16])
	binary.little_endian_put_u32(mut final_header[16..20], header_crc_val)

	mut chunk0_key := []u8{len: 32}
	mut chunk0_nonce_arr := []u64{len: 1}
	derive_key_and_nonce(key, 0, mut chunk0_key, mut chunk0_nonce_arr)
	chacha_encrypt(final_header, 20, chunk0_key, 0, chunk0_nonce_arr[0], mut final_header)
	
	w.out_file.seek(0, .start)!
	w.out_file.write(final_header)!
	w.out_file.close()
	bar.finish()
}

// ============================================================================
// ARCHIVE EXTRACTION
// ============================================================================
struct BufferedStreamReader {
mut:
	file        os.File
	key         string
	data_buffer []u8
	buf_pos     int
	buf_len     int
	file_offset u64
	eof         bool
	skip_done   bool
}

fn new_buffered_stream_reader(file_path string, key string) !BufferedStreamReader {
	mut f := os.open(file_path)!
	f.seek(20, .start)!
	return BufferedStreamReader{
		file:        f
		key:         key
		data_buffer: []u8{len: chunk_size}
		buf_pos:     0
		buf_len:     0
		file_offset: 20
		eof:         false
		skip_done:   false
	}
}

fn (mut r BufferedStreamReader) close() {
	r.file.close()
}

fn (mut r BufferedStreamReader) read(mut out []u8, count int) bool {
	mut remaining := count
	mut out_pos := 0
	for remaining > 0 {
		if r.buf_pos >= r.buf_len && !r.refill_buffer() { return false }
		
		mut to_copy := remaining
		if r.buf_len - r.buf_pos < remaining {
			to_copy = r.buf_len - r.buf_pos
		}
		copy(mut out[out_pos..out_pos + to_copy], r.data_buffer[r.buf_pos..r.buf_pos + to_copy])
		out_pos += to_copy
		r.buf_pos += to_copy
		remaining -= to_copy
	}
	return true
}

fn (mut r BufferedStreamReader) refill_buffer() bool {
	if r.eof { return false }
	
	mut raw_buffer := []u8{len: chunk_size + tag_size}
	bytes_read := r.file.read(mut raw_buffer) or { 0 }
	
	if bytes_read <= tag_size {
		r.eof = true
		return false
	}
	
	data_len := bytes_read - tag_size
	
	mut chunk_key := []u8{len: 32}
	mut nonce_arr := []u64{len: 1}
	derive_key_and_nonce(r.key, r.file_offset / u64(chunk_size), mut chunk_key, mut nonce_arr)
	nonce := nonce_arr[0]
	
	mut poly_state := []u32{len: 16}
	poly_state[0] = 0x61707865; poly_state[1] = 0x3320646e; poly_state[2] = 0x79622d32; poly_state[3] = 0x6b206574
	for i in 0 .. 8 {
		poly_state[4 + i] = 0
		for j in 0 .. 4 {
			poly_state[4 + i] |= u32(chunk_key[i * 4 + j]) << (j * 8)
		}
	}
	poly_state[12] = 0; poly_state[13] = u32(nonce & 0xFFFFFFFF); poly_state[14] = u32(nonce >> 32); poly_state[15] = 0

	mut poly_keystream := []u32{len: 16}
	chacha_block(poly_state, mut poly_keystream)

	mut poly_key := []u8{len: 32}
	for i in 0 .. 32 {
		poly_key[i] = u8((poly_keystream[i / 4] >> ((i % 4) * 8)) & 0xFF)
	}

	mut computed_tag := []u8{len: 16}
	poly1305_mac(raw_buffer[0..data_len], data_len, poly_key, mut computed_tag)
	
	mut res := u8(0)
	for i in 0 .. tag_size {
		res |= raw_buffer[data_len + i] ^ computed_tag[i]
	}
	if res != 0 {
		panic('Poly1305 Tag verification failed. Archive is corrupt or bad key.')
	}

	chacha_encrypt(raw_buffer[0..data_len], data_len, chunk_key, 1, nonce, mut r.data_buffer)
	
	mut skip := 0
	if !r.skip_done && data_len > 20 {
		skip = 20
	}
	if skip > 0 {
		copy(mut r.data_buffer[0..data_len - skip], r.data_buffer[skip..data_len])
		r.skip_done = true
	}

	r.buf_pos = 0
	r.buf_len = data_len - skip
	r.file_offset += u64(data_len)
	return true
}

fn extract_archive(archive_path string, key string, mut bar ProgressBar) !bool {
	mut extract_dir := os.dir(archive_path)
	if extract_dir == '' { extract_dir = '.' }
	mut extracted_items := []string{}

	bar.set_status('Reading header...')
	mut header_buf := []u8{len: 20}
	
	mut header_file := os.open(archive_path) or {
		eprintln('Cannot open file.')
		return false
	}
	header_file.read(mut header_buf)!
	header_file.close()

	mut chunk0_key := []u8{len: 32}
	mut chunk0_nonce_arr := []u64{len: 1}
	derive_key_and_nonce(key, 0, mut chunk0_key, mut chunk0_nonce_arr)
	chacha_encrypt(header_buf, 20, chunk0_key, 0, chunk0_nonce_arr[0], mut header_buf)

	if header_buf[0] != magic[0] || header_buf[1] != magic[1] || header_buf[2] != magic[2] || header_buf[3] != magic[3] {
		eprintln('Invalid archive format or unsupported version.')
		return false
	}
	
	ver := binary.little_endian_u32(header_buf[4..8])
	if ver != version {
		eprintln('Unsupported version.')
		return false
	}

	header_crc := binary.little_endian_u32(header_buf[16..20])
	calc_crc := crc32_calc(header_buf[0..16])
	if header_crc != calc_crc {
		eprintln('Header CRC32 check failed (wrong password or corrupt file).')
		return false
	}

	entry_count := binary.little_endian_u32(header_buf[8..12])
	content_crc_expected := binary.little_endian_u32(header_buf[12..16])

	bar.set_status('Extracting...')
	file_sz := os.file_size(archive_path)
	if file_sz > 20 {
		bar.set_total(file_sz - 20)
	}

	mut reader := new_buffered_stream_reader(archive_path, key)!
	mut content_crc_obj := CRC32{}
	mut read_buf := []u8{len: chunk_size}
	mut total_extracted := u64(0)

	for _ in 0 .. entry_count {
		mut le_buf := []u8{len: 8}
		if !reader.read(mut le_buf[0..4], 4) { return false }
		content_crc_obj.update(le_buf[0..4])
		
		path_len := binary.little_endian_u32(le_buf[0..4])
		mut rel_path_buf := []u8{len: int(path_len)}
		if path_len > 0 {
			reader.read(mut rel_path_buf, int(path_len))
			content_crc_obj.update(rel_path_buf)
		}
		rel_path := rel_path_buf.bytestr()

		mut is_dir_byte := []u8{len: 1}
		reader.read(mut is_dir_byte, 1)
		content_crc_obj.update(is_dir_byte)

		reader.read(mut le_buf, 8)
		content_crc_obj.update(le_buf)
		content_size := binary.little_endian_u64(le_buf)

		full_path := os.join_path(extract_dir, rel_path)

		if is_dir_byte[0] != 0 {
			os.mkdir_all(full_path) or {}
			extracted_items << full_path
		} else {
			os.mkdir_all(os.dir(full_path)) or {}
			mut out_file := os.create(full_path)!
			extracted_items << full_path
			
			mut remaining := content_size
			for remaining > 0 {
				mut to_read := read_buf.len
				if remaining < u64(read_buf.len) { to_read = int(remaining) }
				
				reader.read(mut read_buf[0..to_read], to_read)
				content_crc_obj.update(read_buf[0..to_read])
				
				out_file.write(read_buf[0..to_read])!
				remaining -= u64(to_read)
				total_extracted += u64(to_read)
				bar.update(total_extracted, '')
			}
			out_file.close()
		}
	}
	reader.close()

	bar.set_status('Verifying...')
	if content_crc_expected != content_crc_obj.finalize() {
		eprintln('Content CRC32 mismatch! Deleting extracted files...')
		for p in extracted_items {
			if os.is_dir(p) {
				os.rmdir_all(p) or {}
			} else {
				os.rm(p) or {}
			}
		}
		bar.finish()
		return false
	}
	bar.finish()
	return true
}

// ============================================================================
// CLI INTERFACE
// ============================================================================
fn get_encryption_key(provided string) string {
	if provided != '' { return provided }
	
	pwd := os.input_password('Enter encryption key: ') or { '' }
	if pwd == '' { return default_key }
	return pwd
}

fn wait_exit(args_len int) {
	$if windows {
		if args_len == 2 {
			print('\nPress Enter to exit...')
			os.get_line()
		}
	}
}

fn main() {
	if os.args.len < 2 {
		println('DCF - Data Cryptography File Tool')
		println('Usage:\n  dcf <file/folder> [-o out.dcf] [-p key]')
		wait_exit(os.args.len)
		exit(1)
	}

	mut inputs := []string{}
	mut custom_output := ''
	mut provided_key := ''
	mut force_encrypt := false
	mut force_decrypt := false
	mut no_progress := false

	mut i := 1
	for i < os.args.len {
		arg := os.args[i]
		if arg == '--encrypt' { force_encrypt = true }
		else if arg == '--decrypt' { force_decrypt = true }
		else if arg == '--no-progress' { no_progress = true }
		else if arg == '-o' && i + 1 < os.args.len {
			i++
			custom_output = os.args[i]
		} else if arg == '-p' && i + 1 < os.args.len {
			i++
			provided_key = os.args[i]
		} else {
			inputs << arg
		}
		i++
	}

	if inputs.len == 0 {
		wait_exit(os.args.len)
		exit(1)
	}

	key := get_encryption_key(provided_key)
	decrypt_mode := force_decrypt || (!force_encrypt && inputs.len == 1 && inputs[0].ends_with('.dcf'))

	if decrypt_mode {
		mut bar := new_progress_bar('Decrypting', 0)
		if no_progress { bar.enabled = false }
		
		ok := extract_archive(inputs[0], key, mut bar) or {
			eprintln('Error: ${err}')
			false
		}
		
		if ok {
			println('Extraction complete.')
			exit(0)
		} else {
			eprintln('Error: Extraction failed')
			wait_exit(os.args.len)
			exit(1)
		}
	} else {
		mut output_path := custom_output
		if output_path == '' {
			output_path = os.file_name(inputs[0]) + '.dcf'
		}

		mut bar := new_progress_bar('Encrypting', 0)
		if no_progress { bar.enabled = false }

		create_archive(inputs, key, output_path, mut bar) or {
			eprintln('Error: ${err}')
			os.rm(output_path) or {}
			wait_exit(os.args.len)
			exit(1)
		}
		
		println('Created: ${output_path} (${os.file_size(output_path)} bytes encrypted)')
		exit(0)
	}
}