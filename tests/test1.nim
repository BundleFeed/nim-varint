# Copyright 2023 Geoffrey Picron.
# SPDX-License-Identifier: (MIT or Apache-2.0)

import unittest
import std/random
import strutils

import varint

test "varint":
  var r1 = initRand(123)
  for i in 0..10000:
    let v = r1.rand(0..high(uint32).int).uint32

    var buf = newSeq[byte](5)

    var p = 0
    buf.writeVaruint32(v, p)
    var p2 = 0
    let v2 = buf.readVaruint32(p2)

    check p == p2
    check v == v2

test "varint extremes":
  for v in [0.uint32, high(uint32)]:
    var buf = newSeq[byte](5)

    var p = 0
    buf.writeVaruint32(v, p)
    var p2 = 0
    let v2 = buf.readVaruint32(p2)

    check v == v2
    check p == p2

test "varint ranges":
  for i in 0..31:
    let v = 1'u32 shl i

    var buf = newSeq[byte](5)

    var p = 0
    buf.writeVaruint32(v, p)
    var p2 = 0
    let v2 = buf.readVaruint32(p2)

    check p == p2
    check v == v2

test "varint ranges B64 first 65":
  for i in 0..65:
    let v = i.uint32
    var buf = newString(7)
    var p = 0
    buf.writeVaruint32Base64(v, p)
    var p2 = 0
    let v2 = buf.readVaruint32Base64(p2)

    check p == p2
    check v == v2


test "varint ranges B64":
  for i in 0..31:
    let v = 1'u32 shl i
    var buf = newString(7)

    var p = 0
    buf.writeVaruint32Base64(v, p)
    var p2 = 0
    let v2 = buf.readVaruint32Base64(p2)

    check p == p2
    check v == v2


test "varintB64 random":
  var r1 = initRand(123)
  for i in 0..10000:
    let v = r1.rand(0..high(uint32).int).uint32

    var buf = newString(7)

    var p = 0
    buf.writeVaruint32Base64(v, p)
    var p2 = 0
    let v2 = buf.readVaruint32Base64(p2)

    check p == p2
    check v == v2

test "varint B64 extremes":
  for v in [0.uint32, high(uint32)]:
    var buf = newString(7)

    var p = 0
    buf.writeVaruint32Base64(v, p)
    var p2 = 0
    let v2 = buf.readVaruint32Base64(p2)

    check v == v2
    check p == p2

