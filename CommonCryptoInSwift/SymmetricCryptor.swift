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
    case DES        // DES standard, 64 bits key
    case DES40      // DES, 40 bits key
    case TRIPLEDES  // 3DES, 192 bits key
    case RC4_40     // RC4, 40 bits key
    case RC4_128    // RC4, 128 bits key
    case RC2_40     // RC2, 40 bits key
    case RC2_128    // RC2, 128 bits key
    case AES_128    // AES, 128 bits key
    case AES_256    // AES, 256 bits key
    
    // returns the CCAlgorithm associated with this SymmetricCryptorAlgorithm
    func ccAlgorithm() -> CCAlgorithm {
        switch (self) {
        case DES: return CCAlgorithm(kCCAlgorithmDES)
        case DES40: return CCAlgorithm(kCCAlgorithmDES)
        case TRIPLEDES: return CCAlgorithm(kCCAlgorithm3DES)
        case RC4_40: return CCAlgorithm(kCCAlgorithmRC4)
        case RC4_128: return CCAlgorithm(kCCAlgorithmRC4)
        case RC2_40: return CCAlgorithm(kCCAlgorithmRC2)
        case RC2_128: return CCAlgorithm(kCCAlgorithmRC2)
        case AES_128: return CCAlgorithm(kCCAlgorithmAES)
        case AES_256: return CCAlgorithm(kCCAlgorithmAES)
        }
    }
    
    // Returns the needed size for the IV to be used in the algorithm (0 if no IV is needed).
    func requiredIVSize(options: CCOptions) -> Int {
        // if kCCOptionECBMode is specified, no IV is needed.
        if options & CCOptions(kCCOptionECBMode) != 0 { return 0 }
        // else depends on algorithm
        switch (self) {
        case DES: return kCCBlockSizeDES
        case DES40: return kCCBlockSizeDES
        case TRIPLEDES: return kCCBlockSize3DES
        case RC4_40: return 0
        case RC4_128: return 0
        case RC2_40: return kCCBlockSizeRC2
        case RC2_128: return kCCBlockSizeRC2
        case AES_128: return kCCBlockSizeAES128
        case AES_256: return kCCBlockSizeAES128 // AES256 still requires 256 bits IV
        }
    }
    
    func requiredKeySize() -> Int {
        switch (self) {
        case DES: return kCCKeySizeDES
        case DES40: return 5 // 40 bits = 5x8
        case TRIPLEDES: return kCCKeySize3DES
        case RC4_40: return 5
        case RC4_128: return 16 // RC4 128 bits = 16 bytes
        case RC2_40: return 5
        case RC2_128: return kCCKeySizeMaxRC2 // 128 bits
        case AES_128: return kCCKeySizeAES128
        case AES_256: return kCCKeySizeAES256
        }
    }
    
    func requiredBlockSize() -> Int {
        switch (self) {
        case DES: return kCCBlockSizeDES
        case DES40: return kCCBlockSizeDES
        case TRIPLEDES: return kCCBlockSize3DES
        case RC4_40: return 0
        case RC4_128: return 0
        case RC2_40: return kCCBlockSizeRC2
        case RC2_128: return kCCBlockSizeRC2
        case AES_128: return kCCBlockSizeAES128
        case AES_256: return kCCBlockSizeAES128 // AES256 still requires 128 bits IV
        }
    }
}

enum SymmetricCryptorError: ErrorType {
    case MissingIV
    case CryptOperationFailed
    case WrongInputData
    case UnknownError
}

class SymmetricCryptor: NSObject {
    // properties
    var algorithm: SymmetricCryptorAlgorithm    // Algorithm
    var options: CCOptions                      // Options (i.e: kCCOptionECBMode + kCCOptionPKCS7Padding)
    var iv: NSData?                             // Initialization Vector

    init(algorithm: SymmetricCryptorAlgorithm, options: Int) {
        self.algorithm = algorithm
        self.options = CCOptions(options)
    }
    
    convenience init(algorithm: SymmetricCryptorAlgorithm, options: Int, iv: String, encoding: UInt = NSUTF8StringEncoding) {
        self.init(algorithm: algorithm, options: options)
        self.iv = iv.dataUsingEncoding(encoding)
    }
    
    func crypt(string string: String, key: String) throws -> NSData {
        do {
            if let data = string.dataUsingEncoding(NSUTF8StringEncoding) {
                return try self.cryptoOperation(data, key: key, operation: CCOperation(kCCEncrypt))
            } else { throw SymmetricCryptorError.WrongInputData }
        } catch {
            throw(error)
        }
    }
    
    func crypt(data data: NSData, key: String) throws -> NSData {
        do {
            return try self.cryptoOperation(data, key: key, operation: CCOperation(kCCEncrypt))
        } catch {
            throw(error)
        }
    }
    
    func decrypt(data: NSData, key: String) throws -> NSData  {
        do {
            return try self.cryptoOperation(data, key: key, operation: CCOperation(kCCDecrypt))
        } catch {
            throw(error)
        }
    }
    
    internal func cryptoOperation(inputData: NSData, key: String, operation: CCOperation) throws -> NSData {
        // Validation checks.
        if iv == nil && (self.options & CCOptions(kCCOptionECBMode) == 0) {
            throw(SymmetricCryptorError.MissingIV)
        }
        
        // Prepare data parameters
        let keyData: NSData! = key.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
        let keyBytes         = UnsafePointer<Void>(keyData.bytes)
        let keyLength        = size_t(algorithm.requiredKeySize())
        let dataLength       = Int(inputData.length)
        let dataBytes        = UnsafePointer<Void>(inputData.bytes)
        let bufferData       = NSMutableData(length: Int(dataLength) + algorithm.requiredBlockSize())!
        let bufferPointer    = UnsafeMutablePointer<Void>(bufferData.mutableBytes)
        let bufferLength     = size_t(bufferData.length)
        let ivBuffer         = iv == nil ? nil : UnsafePointer<Void>(iv!.bytes)
        var bytesDecrypted = Int(0)
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
            bufferData.length = bytesDecrypted // Adjust buffer size to real bytes
            return bufferData as NSData
        } else {
            print("Error in crypto operation: \(cryptStatus)")
            throw(SymmetricCryptorError.CryptOperationFailed)
        }
    }
    
    // MARK: - Random methods
    
    class func randomDataOfLength(length: Int) -> NSData? {
        let mutableData = NSMutableData(length: length)!
        let bytes = UnsafeMutablePointer<UInt8>(mutableData.mutableBytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, length, bytes)
        return status == 0 ? mutableData as NSData : nil
    }
    
    class func randomStringOfLength(length:Int) -> String {
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
