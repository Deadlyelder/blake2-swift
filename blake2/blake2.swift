//
//  blake2.swift
//  blake2
//
//  Created by Sankalp on 1/4/22.
//

import Foundation

struct Blake2 {
    struct blake2_ctx {
                var b: [UInt8]
                var h: [UInt64]
                var t: [UInt64]
                var c: UInt64
                var outlen:UInt64
                init() {
                    b = [UInt8](repeating: 0, count: 128)
                    h = [UInt64](repeating: 0, count: 8)
                    t = [UInt64](repeating: 0, count: 2)
                    c = 0
                    outlen = 0
                }
            }
            
            static func ROTR64(_ x: UInt64, _ y: UInt64) -> UInt64 {
                return (((x) >> (y)) ^ ((x) << (64 - (y))))
            }
            

            static func B2B_GET64(_ p: [UInt8], index: Int) -> UInt64 {
                return
                    (UInt64(p[0 + index])) ^
                    (UInt64(p[1 + index]) << 8) ^
                    (UInt64(p[2 + index]) << 16) ^
                    (UInt64(p[3 + index]) << 24) ^
                    (UInt64(p[4 + index]) << 32) ^
                    (UInt64(p[5 + index]) << 40) ^
                    (UInt64(p[6 + index]) << 48) ^
                    (UInt64(p[7 + index]) << 56)
            }

            static func B2B_G(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d :Int, _ x:UInt64, _ y:UInt64) {
                assert(v.count == 16)
                v[a] = v[a] &+ v[b] &+ x
                v[d] = ROTR64(v[d] ^ v[a], 32)
                v[c] = v[c] &+ v[d]
                v[b] = ROTR64(v[b] ^ v[c], 24)
                v[a] = v[a] &+ v[b] &+ y
                v[d] = ROTR64(v[d] ^ v[a], 16)
                v[c] = v[c] &+ v[d]
                v[b] = ROTR64(v[b] ^ v[c], 63)
            }

            static let blake2_iv:[UInt64] = [
                0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
                0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
                0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
                0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
            ]

            static func blake2_compress(_ ctx: inout blake2_ctx, _ last: Int) {
                let sigma:[[Int]] = [
                    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ],
                    [ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 ],
                    [ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 ],
                    [ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 ],
                    [ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 ],
                    [ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 ],
                    [ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 ],
                    [ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 ],
                    [ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 ],
                    [ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 ],
                    [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ],
                    [ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 ]
                ]
                var v = [UInt64](repeating: 0, count: 16)
                var m = [UInt64](repeating: 0, count: 16)
                
                for i in 0..<8 {
                    v[i] = ctx.h[i]
                    v[i + 8] = blake2_iv[i]
                }
                
                v[12] ^= ctx.t[0]
                v[13] ^= ctx.t[1]
                if last != 0 {
                    v[14] = ~v[14]
                }
                
                for i in 0..<16 {
                    m[i] = B2B_GET64(ctx.b, index: 8 * i)
                }
                
                for i in 0..<12 {
                    B2B_G( &v, 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]])
                    B2B_G( &v, 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]])
                    B2B_G( &v, 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]])
                    B2B_G( &v, 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]])
                    B2B_G( &v, 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]])
                    B2B_G( &v, 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]])
                    B2B_G( &v, 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]])
                    B2B_G( &v, 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]])
                }
            
                for i in 0..<8 {
                    ctx.h[i] ^= v[i] ^ v[i + 8]
                }
            }

            static func blake2_init(_ ctx: inout blake2_ctx, _ outlen: UInt64, _ key:[UInt8], _ keylen: UInt64) -> Int {
                if outlen == 0 || outlen > 64 || keylen > 64 {
                    return -1
                }
                
                for i in 0..<8 {
                    ctx.h[i] = blake2_iv[i]
                }
                
                ctx.h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen
                ctx.t[0] = 0
                ctx.t[1] = 0
                ctx.c = 0
                ctx.outlen = outlen

                for i in Int(keylen) ..<  128 {
                    ctx.b[i] = 0
                }
                if keylen > 0 {
                    blake2_update(&ctx, key, keylen)
                    ctx.c = 128
                }
                return 0
            }

            static func blake2_update(_ ctx: inout blake2_ctx, _ data: [UInt8], _ inlen: UInt64) {
                for i in 0..<Int(inlen) {
                    if ctx.c == 128 {
                        ctx.t[0] += ctx.c
                        if ctx.t[0] < ctx.c {
                            ctx.t[1] += 1
                        }
                        blake2_compress(&ctx, 0)
                        ctx.c = 0
                    }
                    ctx.b[Int(ctx.c)] = data[i]
                    ctx.c += 1
                }
            }

            static func blake2_final(_ ctx: inout blake2_ctx, _ outdata: inout [UInt8]) {
                ctx.t[0] += ctx.c
                if ctx.t[0] < ctx.c {
                    ctx.t[1] += 1
                }
                
                while ctx.c < 128 {
                    ctx.b[Int(ctx.c)] = 0
                    ctx.c += 1
                }
                blake2_compress(&ctx, 1)
                
                for i in 0 ..< Int(ctx.outlen) {
                    outdata[i] = UInt8((ctx.h[i >> 3] >> (8 * (i & 7))) & 0xFF)
                }
            }

            static func blake2(_ outdata: inout [UInt8], _ outlen: UInt64, _ key: [UInt8], _ keylen: UInt64, _ indata: [UInt8], _ inlen: UInt64) -> Int {
                var ctx = blake2_ctx()
                if blake2_init(&ctx, outlen, key, keylen) != 0 {
                    return -1
                }
                blake2_update(&ctx, indata, inlen)
                blake2_final(&ctx, &outdata)
                return 0
            }
            
            static func hash(data: [UInt8]) -> [UInt8] {
                var outdata = [UInt8](repeating: 0, count:64)
                if blake2(&outdata, 64, [], 0, data, UInt64(data.count)) != 0 {
                    return [UInt8](repeating: 0, count: 64)
                }
                return outdata
            }
}
