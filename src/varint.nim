# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import strutils

func writeVaruint32*[BB](buf: var BB, v: uint32, p: var int) {.inline.} =
  if v < 0x80:
    buf[p] = typeof(buf[0])(byte(v))
    p+=1
  elif v < 0x4000:
    buf[p] = typeof(buf[0])(byte(v or 0x80))
    buf[p+1] = typeof(buf[0])(byte(v shr 7))
    p+=2
  elif v < 0x200000:
    buf[p] = typeof(buf[0])(byte(v or 0x80))
    buf[p+1] = typeof(buf[0])(byte((v shr 7) or 0x80))
    buf[p+2] = typeof(buf[0])(byte(v shr 14))
    p+=3
  elif v < 0x10000000:
    buf[p] = typeof(buf[0])(byte(v or 0x80))
    buf[p+1] = typeof(buf[0])(byte((v shr 7) or 0x80))
    buf[p+2] = typeof(buf[0])(byte((v shr 14) or 0x80))
    buf[p+3] = typeof(buf[0])(byte(v shr 21))
    p+=4
  else:
    buf[p] = typeof(buf[0])(byte(v or 0x80))
    buf[p+1] = typeof(buf[0])(byte((v shr 7) or 0x80))
    buf[p+2] = typeof(buf[0])(byte((v shr 14) or 0x80))
    buf[p+3] = typeof(buf[0])(byte((v shr 21) or 0x80))
    buf[p+4] = typeof(buf[0])(byte(v shr 28))
    p+=5

template writeVaruint32*[BB](buf: var BB, v: uint32) =
  var p = 0
  writeVaruint32(buf, v, p)


template readVaruint32*[BB](data: BB, p: var int): uint32 =
  var b: uint8 = data[p]
  var result = uint32(b and 0x7f)
  inc p

  for i in 0..<4:
    if (b and 0x80) != 0: 
      b = data[p]
      result += uint32(b and 0x7f) shl (7 + 7*i)
      inc p
    else:
      break

  if (b and 0x80) != 0:
    raise newException(Exception, "Malformed Varint")
  
  result

template readVaruint32*[BB](data: BB): uint32 =
  var p = 0
  readVaruint32(data, p)

template lenVaruint32*(v: uint32): int =
  if v < 0x80:
    1
  elif v < 0x4000:
    2
  elif v < 0x200000:
    3
  elif v < 0x10000000:
    4
  else:
    5

# variant that uses 6 bits words (base64 equivalent), instead of 8 bits words,
# so bit 0 to 4 are used for the value, and bit 5 is used to indicate if there is more data to read

template lenVaruint32Base64*(v: uint32): int =
  var val = v
  var result = 1
  while true:
    if val >= 0x20:
      val = val shr 5
      result+=1
    else:
      break
  result

const
  cb64 = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_']

func writeVaruint32Base64*(buf: var string, v: uint32, p: var int) {.inline.} =
  # write using base64 encoding
  # 6 bits per char, 5 bits of value, 1 bit of continuation
  var val = v
  while true:
    if val >= 0x20:
      buf[p] = cb64[(val or 0x20) and 0x3f]
      val = val shr 5
      p+=1
    else:
      buf[p] = cb64[val and 0x3f]
      p+=1
      break
  
template writeVaruint32Base64*(buf: var string, v: uint32) =
  var p = 0
  writeVaruint32Base64(buf, v, p)


const
  invalidChar = 255


proc initDecodeTable(): array[256, byte] =
  # computes a decode table at compile time
  for i in 0 ..< 256:
    result[i] = byte(invalidChar)
  for i in 0 ..< 64:
    let l = cb64[i]
    result[byte(l)] = byte(i)

const
  decodeTable = initDecodeTable()

template readVaruint32Base64*(data: string | cstring, p: var int): uint32 =
  # read using base64 encoding
  # 6 bits per char, 5 bits of value, 1 bit of continuation

  var b: byte = decodeTable[byte(data[p])]
  if unlikely(b == invalidChar):
    raise newException(ValueError, "Malformed VaruintBase64")
  var result = uint32(b and 0x1f)
  inc p

  for i in 0..<6:
    if (b and 0x20) != 0: 
      b = decodeTable[byte(data[p])]
      if unlikely(b == invalidChar):
        raise newException(ValueError, "Malformed VaruintBase64")
      result += uint32(b and 0x1f) shl (5 + 5*i)
      inc p
    else:
      break

  if (b and 0x40) != 0:
    raise newException(ValueError, "Malformed VaruintBase64")
  
  result

template readVaruint32Base64*(data: string | cstring): uint32 =
  # read using base64 encoding
  # 6 bits per char, 5 bits of value, 1 bit of continuation

  var p = 0
  readVaruint32Base64(data, p)

template toVaruint32Base64*(x: uint32): string =
  let v = x
  var buf = newString(lenVaruint32Base64(v))
  var p = 0
  writeVaruint32Base64(buf, v, p)
  buf
  