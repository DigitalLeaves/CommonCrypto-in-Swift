//
//  SymmetricCryptor
//  CommonCryptoInSwift
//
//  Created by Ignacio Nieto Carvajal on 9/8/15.
//  Copyright © 2015 Ignacio Nieto Carvajal. All rights reserved.
//

import UIKit

private let kSymmetricCryptorRandomStringGeneratorCharset: [Character] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".characters.map({$0})

enum SymmetricCryptorAlgorithm {
    case des        // DES standard, 64 bits key
    case des40      // DES, 40 bits key
    case tripledes  // 3DES, 192 bits key
    case rc4_40     // RC4, 40 bits key
    case rc4_128    // RC4, 128 bits key
    case rc2_40     // RC2, 40 bits key
    case rc2_128    // RC2, 128 bits key
    case aes_128    // AES, 128 bits key
    case aes_256    // AES, 256 bits key
    
    // returns the CCAlgorithm associated with this SymmetricCryptorAlgorithm
    func ccAlgorithm() -> CCAlgorithm {
        switch (self) {
        case .des: return CCAlgorithm(kCCAlgorithmDES)
        case .des40: return CCAlgorithm(kCCAlgorithmDES)
        case .tripledes: return CCAlgorithm(kCCAlgorithm3DES)
        case .rc4_40: return CCAlgorithm(kCCAlgorithmRC4)
        case .rc4_128: return CCAlgorithm(kCCAlgorithmRC4)
        case .rc2_40: return CCAlgorithm(kCCAlgorithmRC2)
        case .rc2_128: return CCAlgorithm(kCCAlgorithmRC2)
        case .aes_128: return CCAlgorithm(kCCAlgorithmAES)
        case .aes_256: return CCAlgorithm(kCCAlgorithmAES)
        }
    }
    
    // Returns the needed size for the IV to be used in the algorithm (0 if no IV is needed).
    func requiredIVSize(_ options: CCOptions) -> Int {
        // if kCCOptionECBMode is specified, no IV is needed.
        if options & CCOptions(kCCOptionECBMode) != 0 { return 0 }
        // else depends on algorithm
        switch (self) {
        case .des: return kCCBlockSizeDES
        case .des40: return kCCBlockSizeDES
        case .tripledes: return kCCBlockSize3DES
        case .rc4_40: return 0
        case .rc4_128: return 0
        case .rc2_40: return kCCBlockSizeRC2
        case .rc2_128: return kCCBlockSizeRC2
        case .aes_128: return kCCBlockSizeAES128
        case .aes_256: return kCCBlockSizeAES128 // AES256 still requires 256 bits IV
        }
    }
    
    func requiredKeySize() -> Int {
        switch (self) {
        case .des: return kCCKeySizeDES
        case .des40: return 5 // 40 bits = 5x8
        case .tripledes: return kCCKeySize3DES
        case .rc4_40: return 5
        case .rc4_128: return 16 // RC4 128 bits = 16 bytes
        case .rc2_40: return 5
        case .rc2_128: return kCCKeySizeMaxRC2 // 128 bits
        case .aes_128: return kCCKeySizeAES128
        case .aes_256: return kCCKeySizeAES256
        }
    }
    
    func requiredBlockSize() -> Int {
        switch (self) {
        case .des: return kCCBlockSizeDES
        case .des40: return kCCBlockSizeDES
        case .tripledes: return kCCBlockSize3DES
        case .rc4_40: return 0
        case .rc4_128: return 0
        case .rc2_40: return kCCBlockSizeRC2
        case .rc2_128: return kCCBlockSizeRC2
        case .aes_128: return kCCBlockSizeAES128
        case .aes_256: return kCCBlockSizeAES128 // AES256 still requires 128 bits IV
        }
    }
}

enum SymmetricCryptorError: Error {
    case missingIV
    case cryptOperationFailed
    case wrongInputData
    case unknownError
}

class SymmetricCryptor: NSObject {
    // properties
    var algorithm: SymmetricCryptorAlgorithm    // Algorithm
    var options: CCOptions                      // Options (i.e: kCCOptionECBMode + kCCOptionPKCS7Padding)
    var iv: Data?                             // Initialization Vector

    init(algorithm: SymmetricCryptorAlgorithm, options: Int) {
        self.algorithm = algorithm
        self.options = CCOptions(options)
    }
    
    convenience init(algorithm: SymmetricCryptorAlgorithm, options: Int, iv: String, encoding: String.Encoding = String.Encoding.utf8) {
        self.init(algorithm: algorithm, options: options)
        self.iv = iv.data(using: encoding)
    }
    
    func crypt(string: String, key: String) throws -> Data {
        do {
            if let data = string.data(using: String.Encoding.utf8) {
                return try self.cryptoOperation(data, key: key, operation: CCOperation(kCCEncrypt))
            } else { throw SymmetricCryptorError.wrongInputData }
        } catch {
            throw(error)
        }
    }
    
    func crypt(data: Data, key: String) throws -> Data {
        do {
            return try self.cryptoOperation(data, key: key, operation: CCOperation(kCCEncrypt))
        } catch {
            throw(error)
        }
    }
    
    func decrypt(_ data: Data, key: String) throws -> Data  {
        do {
            return try self.cryptoOperation(data, key: key, operation: CCOperation(kCCDecrypt))
        } catch {
            throw(error)
        }
    }
    
    internal func cryptoOperation(_ inputData: Data, key: String, operation: CCOperation) throws -> Data {
        // Validation checks.
        if iv == nil && (self.options & CCOptions(kCCOptionECBMode) == 0) {
            throw(SymmetricCryptorError.missingIV)
        }
        
        // Prepare data parameters
        let keyData: Data! = key.data(using: String.Encoding.utf8, allowLossyConversion: false)!
        let keyBytes = keyData.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        }
        //let keyBytes         = keyData.bytes.bindMemory(to: Void.self, capacity: keyData.count)
        let keyLength        = size_t(algorithm.requiredKeySize())
        let dataLength       = Int(inputData.count)
        let dataBytes        = inputData.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        }
        var bufferData       = Data(count: Int(dataLength) + algorithm.requiredBlockSize())
        let bufferPointer    = bufferData.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        let bufferLength     = size_t(bufferData.count)
        let ivBuffer: UnsafePointer<UInt8>? = (iv == nil) ? nil : iv!.withUnsafeBytes({ (bytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return bytes
        })
        var bytesDecrypted   = Int(0)
        // Perform operation
        let cryptStatus = CCCrypt(
            operation,                  // Operation
            algorithm.ccAlgorithm(),    // Algorithm
            options,                    // Options
            keyBytes,                   // key data
            keyLength,                  // key length
            ivBuffer,                   // IV buffer
            dataBytes,                  // input data
            dataLength,                 // input length
            bufferPointer,              // output buffer
            bufferLength,               // output buffer length
            &bytesDecrypted)            // output bytes decrypted real length
        if Int32(cryptStatus) == Int32(kCCSuccess) {
            bufferData.count = bytesDecrypted // Adjust buffer size to real bytes
            return bufferData as Data
        } else {
            print("Error in crypto operation: \(cryptStatus)")
            throw(SymmetricCryptorError.cryptOperationFailed)
        }
    }
    
    // MARK: - Random methods
    
    class func randomDataOfLength(_ length: Int) -> Data? {
        var mutableData = Data(count: length)
        let bytes = mutableData.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            return bytes
        }
        let status = SecRandomCopyBytes(kSecRandomDefault, length, bytes)
        return status == 0 ? mutableData as Data : nil
    }
    
    class func randomStringOfLength(_ length:Int) -> String {
        var string = ""
        for _ in (1...length) {
            string.append(kSymmetricCryptorRandomStringGeneratorCharset[Int(arc4random_uniform(UInt32(kSymmetricCryptorRandomStringGeneratorCharset.count) - 1))])
        }
        return string
    }
    
    func setRandomIV() {
        let length = self.algorithm.requiredIVSize(self.options)
        self.iv = SymmetricCryptor.randomDataOfLength(length)
    }
}
