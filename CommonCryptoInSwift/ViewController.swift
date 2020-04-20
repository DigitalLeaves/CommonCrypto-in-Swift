//
//  ViewController.swift
//  CommonCryptoInSwift
//
//  Created by Ignacio Nieto Carvajal on 9/8/15.
//  Copyright © 2015 Ignacio Nieto Carvajal. All rights reserved.
//

import UIKit
fileprivate func < <T : Comparable>(lhs: T?, rhs: T?) -> Bool {
  switch (lhs, rhs) {
  case let (l?, r?):
    return l < r
  case (nil, _?):
    return true
  default:
    return false
  }
}


class ViewController: UIViewController {
    // outlets && buttons
    @IBOutlet weak var clearTextView: UITextView!
    @IBOutlet weak var cypheredTextView: UITextView!
    @IBOutlet weak var symmetricKeyLabel: UITextField!
    
    @IBOutlet weak var desButton: UIButton!
    @IBOutlet weak var tripledesButton: UIButton!
    @IBOutlet weak var rc4Button: UIButton!
    @IBOutlet weak var rc2Button: UIButton!
    @IBOutlet weak var aesButton: UIButton!
    @IBOutlet weak var pkcs7Button: UIButton!
    @IBOutlet weak var ebcButton: UIButton!
    
    // data
    var selectedAlgorithm: SymmetricCryptorAlgorithm = .des
    var pkcs7Padding = false
    var useEcbMode = false
    var clearText: String = "Sed posuere consectetur est at lobortis. Donec id elit non mi porta gravida at eget metus. Vestibulum id ligula porta felis euismod semper. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi leo risus, porta ac consectetur ac, vestibulum at eros. Vivamus sagittis lacus vel augue laoreet rutrum faucibus dolor auctor."
    var cypherText: Data?
    var iv: Data?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        clearTextView.text = clearText
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    // MARK: - Button actions
    @IBAction func generateKey(_ sender: UIButton!) {
        let key = SymmetricCryptor.randomStringOfLength(selectedAlgorithm.requiredKeySize())
        self.symmetricKeyLabel.text = key
    }
    
    @IBAction func cypher(_ sender: AnyObject) {
        // validity checks
        if clearTextView.text?.count < 1 {
            showAlertWithMessage("Please enter a valid clear text.")
            return
        } else { clearText = clearTextView.text! }
        // build cryptor
        let options = getCypheringOptions()
        let cypher = SymmetricCryptor(algorithm: selectedAlgorithm, options: options)
        if !useEcbMode { // IV needed if not in ECB mode
            setIV(cypher)
        }
        if symmetricKeyLabel.text?.count < 1 { generateKey(nil) }
        // perform cyphering
        do {
            cypherText = try cypher.crypt(string: clearText, key: symmetricKeyLabel.text!) as Data
            if let cypheredString = String(data: cypherText!, encoding: String.Encoding.utf8) {
                cypheredTextView.text = cypheredString as String
            } else {
                cypheredTextView.text = cypherText?.hexDescription ?? "-"
            }
            clearTextView.text = ""
        } catch {
            self.showAlertWithMessage("Unable to perform cyphering on given text. \(error). Try enabling PKCS7 padding.")
        }
    }
    
    @IBAction func decypher(_ sender: AnyObject) {
        // validity checks
        if cypherText == nil {
            showAlertWithMessage("No cypher text to decypher")
            return
        } else { clearText = clearTextView.text! }
        // build cryptor
        let options = getCypheringOptions()
        let cypher = SymmetricCryptor(algorithm: selectedAlgorithm, options: options)
        if !useEcbMode { // IV needed if not in ECB mode
            setIV(cypher)
        }
        if symmetricKeyLabel.text?.count < 1 { generateKey(nil) }
        // perform cyphering
        do {
            let clearData = try cypher.decrypt(cypherText!, key: symmetricKeyLabel.text!)
            if let clearDataAsString = String(data: clearData, encoding: String.Encoding.utf8) {
                clearText = clearDataAsString as String
                clearTextView.text = clearText
                cypherText = nil
            } else { clearTextView.text = "(Unable to generate a valid response string, probably wrong key or parameters, showing as Data instead): \(clearData)" }
            cypheredTextView.text = ""
        } catch {
            self.showAlertWithMessage("Unable to perform decyphering on given text. \(error)")
        }

    }
    
    @IBAction func selectDESAlgorithm(_ sender: UIButton) {
        selectedAlgorithm = .des
        selectAlgorithmButton(sender)
    }
    
    @IBAction func select3DESAlgorithm(_ sender: UIButton) {
        selectedAlgorithm = .tripledes
        selectAlgorithmButton(sender)
    }
    
    @IBAction func selectRC4Algorithm(_ sender: UIButton) {
        selectedAlgorithm = .rc4_128
        selectAlgorithmButton(sender)
    }
    
    @IBAction func selectRC2Algorithm(_ sender: UIButton) {
        selectedAlgorithm = .rc2_128
        selectAlgorithmButton(sender)
    }
    
    @IBAction func visuallySelectAESAlgorithm(_ sender: UIButton) {
        selectedAlgorithm = .aes_128
        selectAlgorithmButton(sender)
    }
    
    @IBAction func pkcs7ButtonTouched(_ sender: UIButton) {
        self.pkcs7Padding = !self.pkcs7Padding
        UIView.animate(withDuration: 0.5, animations: { () -> Void in
            self.pkcs7Button.alpha = self.pkcs7Padding ? 1.0 : 0.20
        }) 
    }
    
    @IBAction func ebcButtonTouched(_ sender: UIButton) {
        self.useEcbMode = !self.useEcbMode
        UIView.animate(withDuration: 0.5, animations: { () -> Void in
            self.ebcButton.alpha = self.useEcbMode ? 1.0 : 0.20
        }) 
    }
    
    fileprivate func selectAlgorithmButton(_ button: UIButton) {
        self.symmetricKeyLabel.text = ""
        var allButtons: [UIButton] = [desButton, tripledesButton, rc4Button, rc2Button, aesButton]
        if let index = allButtons.firstIndex(of: button) {
            allButtons.remove(at: index)
            UIView.animate(withDuration: 0.5, animations: { () -> Void in
                for buttonToFade in allButtons { buttonToFade.alpha = 0.20 }
                button.alpha = 1.0
            })
        }
    }
    
    func setIV(_ cypher: SymmetricCryptor) {
        if iv == nil {
            cypher.setRandomIV()
            iv = cypher.iv as Data?
        } else { cypher.iv = iv! }
    }
    
    func getCypheringOptions() -> Int {
        // build cyphering options
        var options = 0
        if self.pkcs7Padding { options |= kCCOptionPKCS7Padding }
        if self.useEcbMode { options |= kCCOptionECBMode }
        return options
    }

    // MARK: - UIViewController alerts options.
    func showAlertWithMessage(_ msg: String, completion: (() -> Void)? = nil) {
        let alert = UIAlertController(title: nil, message: msg, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Ok", style: .default, handler: nil))
        self.present(alert, animated: true, completion: completion)
    }
    
    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        self.view.endEditing(true)
    }
}

