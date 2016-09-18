//
//  Keychain.swift
//  KeychainSwiftAPI
//
//  Created by Denis Krivitski on 22/7/14.
//  Copyright (c) 2014 Checkmarx. All rights reserved.
//

import Foundation
import Security

public func == (left:Keychain.ResultCode, right:Keychain.ResultCode) -> Bool
{
    return left.toRaw() == right.toRaw()
}

public func != (left:Keychain.ResultCode, right:Keychain.ResultCode) -> Bool {
    return !(left == right)
}

open class Keychain
{
    public init() {}
    /**
    A Swift style wrapper of OSStatus result codes that can be returned from KeyChain functions.
    */

    public enum ResultCode : CustomStringConvertible {
        case errSecSuccess                //  = 0        // No error.
        case errSecUnimplemented          //  = -4       // Function or operation not implemented.
        case errSecParam                  //  = -50      // One or more parameters passed to the function were not valid.
        case errSecAllocate               //  = -108     // Failed to allocate memory.
        case errSecNotAvailable           //  = -25291   // No trust results are available.
        case errSecAuthFailed             //  = -25293   // Authorization/Authentication failed.
        case errSecDuplicateItem          //  = -25299   // The item already exists.
        case errSecItemNotFound           //  = -25300   // The item cannot be found.
        case errSecInteractionNotAllowed  //  = -25308   // Interaction with the Security Server is not allowed.
        case errSecDecode                 //  = -26275   // Unable to decode the provided data.
        case other(OSStatus)
        
        public func toRaw() -> OSStatus
        {
            switch self {
            case .errSecSuccess:                 return  0
            case .errSecUnimplemented:           return -4
            case .errSecParam:                   return -50
            case .errSecAllocate:                return -108
            case .errSecNotAvailable:            return -25291
            case .errSecAuthFailed:              return -25293
            case .errSecDuplicateItem:           return -25299
            case .errSecItemNotFound:            return -25300
            case .errSecInteractionNotAllowed:   return -25308
            case .errSecDecode:                  return -26275
            case let .other(status):             return status
            }
        }
        
        public static func fromRaw(_ status : OSStatus) -> ResultCode
        {
            switch status {
                
            case    0 	 : return ResultCode.errSecSuccess
            case   -4 	 : return ResultCode.errSecUnimplemented
            case   -50 	 : return ResultCode.errSecParam
            case   -108  : return ResultCode.errSecAllocate
            case   -25291: return ResultCode.errSecNotAvailable
            case   -25293: return ResultCode.errSecAuthFailed
            case   -25299: return ResultCode.errSecDuplicateItem
            case   -25300: return ResultCode.errSecItemNotFound
            case   -25308: return ResultCode.errSecInteractionNotAllowed
            case   -26275: return ResultCode.errSecDecode
                
            default: return ResultCode.other(status)
            }
        }
        
        public var description: String { get {
            switch self {
            case .errSecSuccess:                 return "Success"
            case .errSecUnimplemented:           return "Function or operation not implemented."
            case .errSecParam:                   return "One or more parameters passed to the function were not valid."
            case .errSecAllocate:                return "Failed to allocate memory."
            case .errSecNotAvailable:            return "No trust results are available."
            case .errSecAuthFailed:              return "Authorization/Authentication failed."
            case .errSecDuplicateItem:           return "The item already exists."
            case .errSecItemNotFound:            return "The item cannot be found."
            case .errSecInteractionNotAllowed:   return "Interaction with the Security Server is not allowed."
            case .errSecDecode:                  return "Unable to decode the provided data."
            case let .other(status):             return "Error code: \(status)"
            }
        }}
        
        
    }
    
    /**

    A Swift style wrapper of KeyChain attributes dictionary. Class property names correspond to attribute keys,
    property values correspond to attribute values. All properties are of optional type. When a prerty is nil, 
    the corresponding key-value pair will not be added to the attributes dictionary.
    
    For a description of key-value pairs see the documentation of Keychain API.
    */

    open class Query {
        public init(){}
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Item class
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        open var kSecClass : KSecClassValue?
        fileprivate let kSecClassKey = "class"
        public enum KSecClassValue : String {
            
            case kSecClassGenericPassword   = "genp"
            case kSecClassInternetPassword  = "inet"
            case kSecClassCertificate       = "cert"
            case kSecClassKey               = "keys"
            case kSecClassIdentity          = "idnt"
            
        }
        fileprivate func kSecClassAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecClass {
                dic.setObject(v.rawValue, forKey: kSecClassKey as NSCopying)
            }
        }

        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Return data type
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        
        open var kSecReturnData : Bool = false
        fileprivate let kSecReturnDataKey = "r_Data"
        fileprivate func kSecReturnDataAddToDic(_ dic : NSMutableDictionary) {
            if kSecReturnData {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecReturnDataKey as NSCopying)
            }
        }

        open var kSecReturnAttributes : Bool = false
        fileprivate let kSecReturnAttributesKey = "r_Attributes"
        fileprivate func kSecReturnAttributesAddToDic(_ dic : NSMutableDictionary) {
            if kSecReturnAttributes {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecReturnAttributesKey as NSCopying)
            }
        }

        open var kSecReturnRef : Bool = false
        fileprivate let kSecReturnRefKey = "r_Ref"
        fileprivate func kSecReturnRefAddToDic(_ dic : NSMutableDictionary) {
            if kSecReturnRef {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecReturnRefKey as NSCopying)
            }
        }

        open var kSecReturnPersistentRef : Bool = false
        fileprivate let kSecReturnPersistentRefKey = "r_PersistentRef"
        fileprivate func kSecReturnPersistentRefAddToDic(_ dic : NSMutableDictionary) {
            if kSecReturnPersistentRef {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecReturnPersistentRefKey as NSCopying)
            }
        }

        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Value
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        
        open var kSecValueData : Data?
        fileprivate let kSecValueDataKey = "v_Data"
        fileprivate func kSecValueDataAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecValueData {
                dic.setObject(v, forKey: kSecValueDataKey as NSCopying)
            }
        }
        
        
        open var kSecValueRef : KSecValueRefValue?
        fileprivate let kSecValueRefKey = "v_Ref"
        public enum KSecValueRefValue {
            case key(SecKey)
            case certificate(SecCertificate)
            case identity(SecIdentity)
        }
        fileprivate func kSecValueRefAddToDic(_ dic : NSMutableDictionary) {
            if let v = self.kSecValueRef {
                switch v {
                case let .key(val):
                    dic.setObject(val, forKey: self.kSecValueRefKey as NSCopying)
                    
                case let .certificate(val):
                    dic.setObject(val, forKey: self.kSecValueRefKey as NSCopying)
                    
                case let .identity(val):
                    dic.setObject(val, forKey: self.kSecValueRefKey as NSCopying)
                    
                }
            }
        }

        
        open var kSecValuePersistentRef : Data?
        fileprivate let kSecValuePersistentRefKey = "v_PersistentRef"
        fileprivate func kSecValuePersistentRefAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecValuePersistentRef {
                dic.setObject(v, forKey: kSecValuePersistentRefKey as NSCopying)
            }
        }
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Attributes
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
       
        open  var kSecAttrAccessible : KSecAttrAccessibleValue?
        fileprivate let kSecAttrAccessibleKey = "pdmn"
        public enum KSecAttrAccessibleValue : String {
            case kSecAttrAccessibleWhenUnlocked = "ak"
            case kSecAttrAccessibleAfterFirstUnlock = "ck"
            case kSecAttrAccessibleAlways = "dk"
            case kSecAttrAccessibleWhenUnlockedThisDeviceOnly = "aku"
            case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = "cku"
            case kSecAttrAccessibleAlwaysThisDeviceOnly = "dku"
        }
        fileprivate func kSecAttrAccessibleAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrAccessible {
                dic.setObject(v.rawValue, forKey: kSecAttrAccessibleKey as NSCopying)
            }
        }
        
        
        open   var kSecAttrCreationDate : Date?
        fileprivate  let kSecAttrCreationDateKey = "cdat"
        fileprivate func kSecAttrCreationDateAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrCreationDate {
                dic.setObject(v, forKey: kSecAttrCreationDateKey as NSCopying)
            }
        }
        
        open   var kSecAttrModificationDate : Date?
        fileprivate  let kSecAttrModificationDateKey = "mdat"
        fileprivate func kSecAttrModificationDateAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrModificationDate {
                dic.setObject(v, forKey: kSecAttrModificationDateKey as NSCopying)
            }
        }
        
        open var kSecAttrDescription : String?
        fileprivate let kSecAttrDescriptionKey = "desc"
        fileprivate func kSecAttrDescriptionAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrDescription {
                dic.setObject(v, forKey: kSecAttrDescriptionKey as NSCopying)
            }
        }
        
        open var kSecAttrComment : String?
        fileprivate let kSecAttrCommentKey = "icmt"
        fileprivate func kSecAttrCommentAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrComment {
                dic.setObject(v, forKey: kSecAttrCommentKey as NSCopying)
            }
        }
        
        open var kSecAttrCreator : UInt32? // NSNumber with unsigned integer
        fileprivate let kSecAttrCreatorKey = "crtr"
        fileprivate func kSecAttrCreatorAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrCreator {
                dic.setObject(NSNumber(value: v as UInt32), forKey: kSecAttrCreatorKey as NSCopying)
            }
        }
        
        open   var kSecAttrType : UInt32? // NSNumber with unsigned integer
        fileprivate  let kSecAttrTypeKey = "type"
        fileprivate func kSecAttrTypeAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrType {
                dic.setObject(NSNumber(value: v as UInt32), forKey: kSecAttrTypeKey as NSCopying)
            }
        }
        
        open var kSecAttrLabel : String?
        fileprivate let kSecAttrLabelKey = "labl"
        fileprivate func kSecAttrLabelAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrLabel {
                dic.setObject(v, forKey: kSecAttrLabelKey as NSCopying)
            }
        }
        
        open var kSecAttrIsInvisible : Bool = false // NSNumber with bool
        fileprivate let kSecAttrIsInvisibleKey = "invi"
        fileprivate func kSecAttrIsInvisibleAddToDic(_ dic : NSMutableDictionary) {
            if kSecAttrIsInvisible {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrIsInvisibleKey as NSCopying)
            }
        }
        
        open var kSecAttrIsNegative : Bool = false // NSNumber with bool
        fileprivate let kSecAttrIsNegativeKey = "nega"
        fileprivate func kSecAttrIsNegativeAddToDic(_ dic : NSMutableDictionary) {
            if kSecAttrIsNegative {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrIsNegativeKey as NSCopying)
            }
        }

        
        open var kSecAttrAccount : String?
        fileprivate let kSecAttrAccountKey = "acct"
        fileprivate func kSecAttrAccountAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrAccount {
                dic.setObject(v, forKey: kSecAttrAccountKey as NSCopying)
            }
        }
        
        open var kSecAttrService : String?
        fileprivate let kSecAttrServiceKey = "svce"
         fileprivate func kSecAttrServiceAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrService {
                dic.setObject(v, forKey: kSecAttrServiceKey as NSCopying)
            }
        }
        
        open var kSecAttrGeneric : Data?
        fileprivate let kSecAttrGenericKey = "gena"
         fileprivate func kSecAttrGenericAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrGeneric {
                dic.setObject(v, forKey: kSecAttrGenericKey as NSCopying)
            }
        }
        
        open var kSecAttrSecurityDomain : String?
        fileprivate let kSecAttrSecurityDomainKey = "sdmn"
         fileprivate func kSecAttrSecurityDomainAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrSecurityDomain {
                dic.setObject(v, forKey: kSecAttrSecurityDomainKey as NSCopying)
            }
        }
        
        open var kSecAttrServer : String?
        fileprivate let kSecAttrServerKey = "srvr"
         fileprivate func kSecAttrServerAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrServer {
                dic.setObject(v, forKey: kSecAttrServerKey as NSCopying)
            }
        }
        
        open var kSecAttrProtocol : KSecAttrProtocolValue?
        fileprivate let kSecAttrProtocolKey = "ptcl"
        public enum KSecAttrProtocolValue : String {
            case kSecAttrProtocolFTP = "ftp "
            case kSecAttrProtocolFTPAccount = "ftpa"
            case kSecAttrProtocolHTTP = "http"
            case kSecAttrProtocolIRC = "irc "
            case kSecAttrProtocolNNTP = "nntp"
            case kSecAttrProtocolPOP3 = "pop3"
            case kSecAttrProtocolSMTP = "smtp"
            case kSecAttrProtocolSOCKS = "sox "
            case kSecAttrProtocolIMAP = "imap"
            case kSecAttrProtocolLDAP = "ldap"
            case kSecAttrProtocolAppleTalk = "atlk"
            case kSecAttrProtocolAFP = "afp "
            case kSecAttrProtocolTelnet = "teln"
            case kSecAttrProtocolSSH = "ssh "
            case kSecAttrProtocolFTPS = "ftps"
            case kSecAttrProtocolHTTPS = "htps"
            case kSecAttrProtocolHTTPProxy = "htpx"
            case kSecAttrProtocolHTTPSProxy = "htsx"
            case kSecAttrProtocolFTPProxy = "ftpx"
            case kSecAttrProtocolSMB = "smb "
            case kSecAttrProtocolRTSP = "rtsp"
            case kSecAttrProtocolRTSPProxy = "rtsx"
            case kSecAttrProtocolDAAP = "daap"
            case kSecAttrProtocolEPPC = "eppc"
            case kSecAttrProtocolIPP = "ipp "
            case kSecAttrProtocolNNTPS = "ntps"
            case kSecAttrProtocolLDAPS = "ldps"
            case kSecAttrProtocolTelnetS = "tels"
            case kSecAttrProtocolIMAPS = "imps"
            case kSecAttrProtocolIRCS = "ircs"
            case kSecAttrProtocolPOP3S = "pops"
        }
        fileprivate func kSecAttrProtocolAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrProtocol {
                dic.setObject(v.rawValue, forKey: kSecAttrProtocolKey as NSCopying)
            }
        }

        
        
        open var kSecAttrAuthenticationType : KSecAttrAuthenticationTypeValue?
        fileprivate let kSecAttrAuthenticationTypeKey = "atyp"
        public enum KSecAttrAuthenticationTypeValue : String {
            case kSecAttrAuthenticationTypeNTLM = "ntlm"
            case kSecAttrAuthenticationTypeMSN = "msna"
            case kSecAttrAuthenticationTypeDPA = "dpaa"
            case kSecAttrAuthenticationTypeRPA = "rpaa"
            case kSecAttrAuthenticationTypeHTTPBasic = "http"
            case kSecAttrAuthenticationTypeHTTPDigest = "httd"
            case kSecAttrAuthenticationTypeHTMLForm = "form"
            case kSecAttrAuthenticationTypeDefault = "dflt"
        }
        fileprivate func kSecAttrAuthenticationTypeAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrAuthenticationType {
                dic.setObject(v.rawValue, forKey: kSecAttrAuthenticationTypeKey as NSCopying)
            }
        }

        
        open var kSecAttrPort : UInt32? // NSNumber unsigned
        fileprivate let kSecAttrPortKey = "port"
        fileprivate func kSecAttrPortAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrPort {
                dic.setObject(NSNumber(value: v as UInt32), forKey: kSecAttrPortKey as NSCopying)
            }
        }
        
        open var kSecAttrPath : String?
        fileprivate let kSecAttrPathKey = "path"
         fileprivate func kSecAttrPathAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrPath {
                dic.setObject(v, forKey: kSecAttrPathKey as NSCopying)
            }
        }
        
        open var kSecAttrSubject : Data?
        fileprivate let kSecAttrSubjectKey = "subj"
         fileprivate func kSecAttrSubjectAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrSubject {
                dic.setObject(v, forKey: kSecAttrSubjectKey as NSCopying)
            }
        }
        
        open var kSecAttrIssuer : Data?
        fileprivate let kSecAttrIssuerKey = "issr"
         fileprivate func kSecAttrIssuerAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrIssuer {
                dic.setObject(v, forKey: kSecAttrIssuerKey as NSCopying)
            }
        }
        
        open var kSecAttrSerialNumber : Data?
        fileprivate let kSecAttrSerialNumberKey = "slnr"
         fileprivate func kSecAttrSerialNumberAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrSerialNumber {
                dic.setObject(v, forKey: kSecAttrSerialNumberKey as NSCopying)
            }
        }
        
        open var kSecAttrSubjectKeyID : Data?
        fileprivate let kSecAttrSubjectKeyIDKey = "skid"
         fileprivate func kSecAttrSubjectKeyIDAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrSubjectKeyID {
                dic.setObject(v, forKey: kSecAttrSubjectKeyIDKey as NSCopying)
            }
        }
        
        open var kSecAttrPublicKeyHash : Data?
        fileprivate let kSecAttrPublicKeyHashKey = "pkhh"
         fileprivate func kSecAttrPublicKeyHashAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrPublicKeyHash {
                dic.setObject(v, forKey: kSecAttrPublicKeyHashKey as NSCopying)
            }
        }
        
        open var kSecAttrCertificateType : KSecAttrCertificateTypeValue? // NSSNumber
        fileprivate let kSecAttrCertificateTypeKey = "ctyp"
        public enum KSecAttrCertificateTypeValue {
            case standard(CSSM_CERT_TYPE)
            case custom(UInt32)
        }
        public enum CSSM_CERT_TYPE : UInt32 { // CSSM_CERT_TYPE
            case cssm_CERT_UNKNOWN =					0x00
            case cssm_CERT_X_509v1 =					0x01
            case cssm_CERT_X_509v2 =					0x02
            case cssm_CERT_X_509v3 =					0x03
            case cssm_CERT_PGP =						0x04
            case cssm_CERT_SPKI =                       0x05
            case cssm_CERT_SDSIv1 =                     0x06
            case cssm_CERT_Intel =                      0x08
            case cssm_CERT_X_509_ATTRIBUTE =			0x09 /* X.509 attribute cert */
            case cssm_CERT_X9_ATTRIBUTE =               0x0A /* X9 attribute cert */
            case cssm_CERT_TUPLE =                      0x0B
            case cssm_CERT_ACL_ENTRY =                  0x0C
            case cssm_CERT_MULTIPLE =                   0x7FFE
            case cssm_CERT_LAST =                       0x7FFF
            /* Applications wishing to define their own custom certificate
            type should define and publicly document a uint32 value greater
            than the CSSM_CL_CUSTOM_CERT_TYPE */
            case cssm_CL_CUSTOM_CERT_TYPE =             0x08000
        }
        fileprivate func kSecAttrCertificateTypeAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrCertificateType {
                switch v {
                case let .standard(val):
                        dic.setObject(NSNumber(value: val.rawValue as UInt32), forKey: kSecAttrCertificateTypeKey as NSCopying)
                case let .custom(val):
                        dic.setObject(NSNumber(value: val as UInt32), forKey: kSecAttrCertificateTypeKey as NSCopying)
                }
            }
        }
        
        open var kSecAttrCertificateEncoding : KSecAttrCertificateEncodingValue? // NSNumber
        fileprivate let kSecAttrCertificateEncodingKey = "cenc"
        public enum KSecAttrCertificateEncodingValue {
            case standard(CSSM_CERT_ENCODING)
            case custom(UInt32)
        }
        public enum CSSM_CERT_ENCODING : UInt32 {
            case cssm_CERT_ENCODING_UNKNOWN =		0x00
            case cssm_CERT_ENCODING_CUSTOM =		0x01
            case cssm_CERT_ENCODING_BER =			0x02
            case cssm_CERT_ENCODING_DER =			0x03
            case cssm_CERT_ENCODING_NDR =			0x04
            case cssm_CERT_ENCODING_SEXPR =			0x05
            case cssm_CERT_ENCODING_PGP =			0x06
            case cssm_CERT_ENCODING_MULTIPLE =		0x7FFE
            case cssm_CERT_ENCODING_LAST =			0x7FFF
            /* Applications wishing to define their own custom certificate
            encoding should create a uint32 value greater than the
            CSSM_CL_CUSTOM_CERT_ENCODING */
            case cssm_CL_CUSTOM_CERT_ENCODING =		0x8000
        }
        fileprivate func kSecAttrCertificateEncodingAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrCertificateEncoding {
                switch v {
                case let .standard(val):
                    dic.setObject(NSNumber(value: val.rawValue as UInt32), forKey: kSecAttrCertificateEncodingKey as NSCopying)
                case let .custom(val):
                    dic.setObject(NSNumber(value: val as UInt32), forKey: kSecAttrCertificateEncodingKey as NSCopying)
                }
            }
        }

        
        
        open var kSecAttrKeyClass : KSecAttrKeyClassValue?
        fileprivate let kSecAttrKeyClassKey = "kcls"
        public enum KSecAttrKeyClassValue : String {
            case kSecAttrKeyClassPublic = "0"
            case kSecAttrKeyClassPrivate = "1"
            case kSecAttrKeyClassSymmetric = "2"
        }
        fileprivate func kSecAttrKeyClassAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrKeyClass {
                dic.setObject(v.rawValue, forKey: kSecAttrKeyClassKey as NSCopying)
            }
        }
       
        
        open var kSecAttrApplicationLabel : String?
        fileprivate let kSecAttrApplicationLabelKey = "klbl"
        fileprivate func kSecAttrApplicationLabelAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrApplicationLabel {
                dic.setObject(v, forKey: kSecAttrApplicationLabelKey as NSCopying)
            }
        }
        
        open var kSecAttrIsPermanent : Bool? // NSNumber bool
        fileprivate let kSecAttrIsPermanentKey = "perm"
        fileprivate func kSecAttrIsPermanentAddToDic(_ dic : NSMutableDictionary) {
            if (kSecAttrIsPermanent != nil && kSecAttrIsPermanent!) {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrIsPermanentKey as NSCopying)
            }
        }

        
        open var kSecAttrApplicationTag : Data?
        fileprivate let kSecAttrApplicationTagKey = "atag"
        fileprivate func kSecAttrApplicationTagAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrApplicationTag {
                dic.setObject(v, forKey: kSecAttrApplicationTagKey as NSCopying)
            }
        }
        
        open var kSecAttrKeyType : KSecAttrKeyTypeValue? // NSNumber, in practice it is CFString
        fileprivate let kSecAttrKeyTypeKey = "type"
        public enum KSecAttrKeyTypeValue {
            case standard(CSSM_ALGORITHMS)
            case custom(UInt32)
        }
        public enum CSSM_ALGORITHMS : UInt32 {
            case cssm_ALGID_NONE =					0
            case cssm_ALGID_CUSTOM =				1
            case cssm_ALGID_DH =					2
            case cssm_ALGID_PH =					3
            case cssm_ALGID_KEA =					4
            case cssm_ALGID_MD2 =					5
            case cssm_ALGID_MD4 =					6
            case cssm_ALGID_MD5 =					7
            case cssm_ALGID_SHA1 =					8
            case cssm_ALGID_NHASH =					9
            case cssm_ALGID_HAVAL =					10
            case cssm_ALGID_RIPEMD =				11
            case cssm_ALGID_IBCHASH =				12
            case cssm_ALGID_RIPEMAC =				13
            case cssm_ALGID_DES =					14
            case cssm_ALGID_DESX =					15
            case cssm_ALGID_RDES =					16
            case cssm_ALGID_3DES_3KEY_EDE =			17
            case cssm_ALGID_3DES_2KEY_EDE =			18
            case cssm_ALGID_3DES_1KEY_EEE =			19
            //case CSSM_ALGID_3DES_3KEY =           	CSSM_ALGID_3DES_3KEY_EDE
            case cssm_ALGID_3DES_3KEY_EEE =       	20
            //case CSSM_ALGID_3DES_2KEY =           	CSSM_ALGID_3DES_2KEY_EDE
            case cssm_ALGID_3DES_2KEY_EEE =       	21
            //case CSSM_ALGID_3DES_1KEY =				CSSM_ALGID_3DES_3KEY_EEE
            case cssm_ALGID_IDEA =					22
            case cssm_ALGID_RC2 =					23
            case cssm_ALGID_RC5 =					24
            case cssm_ALGID_RC4 =					25
            case cssm_ALGID_SEAL =					26
            case cssm_ALGID_CAST =					27
            case cssm_ALGID_BLOWFISH =				28
            case cssm_ALGID_SKIPJACK =				29
            case cssm_ALGID_LUCIFER =				30
            case cssm_ALGID_MADRYGA =				31
            case cssm_ALGID_FEAL =					32
            case cssm_ALGID_REDOC =					33
            case cssm_ALGID_REDOC3 =				34
            case cssm_ALGID_LOKI =					35
            case cssm_ALGID_KHUFU =					36
            case cssm_ALGID_KHAFRE =				37
            case cssm_ALGID_MMB =					38
            case cssm_ALGID_GOST =					39
            case cssm_ALGID_SAFER =					40
            case cssm_ALGID_CRAB =					41
            case cssm_ALGID_RSA =					42
            case cssm_ALGID_DSA =					43
            case cssm_ALGID_MD5WithRSA =			44
            case cssm_ALGID_MD2WithRSA =			45
            case cssm_ALGID_ElGamal =				46
            case cssm_ALGID_MD2Random =				47
            case cssm_ALGID_MD5Random =				48
            case cssm_ALGID_SHARandom =				49
            case cssm_ALGID_DESRandom =				50
            case cssm_ALGID_SHA1WithRSA =			51
            case cssm_ALGID_CDMF =					52
            case cssm_ALGID_CAST3 =					53
            case cssm_ALGID_CAST5 =					54
            case cssm_ALGID_GenericSecret =			55
            case cssm_ALGID_ConcatBaseAndKey =		56
            case cssm_ALGID_ConcatKeyAndBase =		57
            case cssm_ALGID_ConcatBaseAndData =		58
            case cssm_ALGID_ConcatDataAndBase =		59
            case cssm_ALGID_XORBaseAndData =		60
            case cssm_ALGID_ExtractFromKey =		61
            case cssm_ALGID_SSL3PreMasterGen =		62
            case cssm_ALGID_SSL3MasterDerive =		63
            case cssm_ALGID_SSL3KeyAndMacDerive =	64
            case cssm_ALGID_SSL3MD5_MAC =			65
            case cssm_ALGID_SSL3SHA1_MAC =			66
            case cssm_ALGID_PKCS5_PBKDF1_MD5 =		67
            case cssm_ALGID_PKCS5_PBKDF1_MD2 =		68
            case cssm_ALGID_PKCS5_PBKDF1_SHA1 =		69
            case cssm_ALGID_WrapLynks =				70
            case cssm_ALGID_WrapSET_OAEP =			71
            case cssm_ALGID_BATON =					72
            case cssm_ALGID_ECDSA =					73
            case cssm_ALGID_MAYFLY =				74
            case cssm_ALGID_JUNIPER =				75
            case cssm_ALGID_FASTHASH =				76
            case cssm_ALGID_3DES =					77
            case cssm_ALGID_SSL3MD5 =				78
            case cssm_ALGID_SSL3SHA1 =				79
            case cssm_ALGID_FortezzaTimestamp =		80
            case cssm_ALGID_SHA1WithDSA =			81
            case cssm_ALGID_SHA1WithECDSA =			82
            case cssm_ALGID_DSA_BSAFE =				83
            case cssm_ALGID_ECDH =					84
            case cssm_ALGID_ECMQV =					85
            case cssm_ALGID_PKCS12_SHA1_PBE =		86
            case cssm_ALGID_ECNRA =					87
            case cssm_ALGID_SHA1WithECNRA =			88
            case cssm_ALGID_ECES =					89
            case cssm_ALGID_ECAES =					90
            case cssm_ALGID_SHA1HMAC =				91
            case cssm_ALGID_FIPS186Random =			92
            case cssm_ALGID_ECC =					93
            case cssm_ALGID_MQV =					94
            case cssm_ALGID_NRA =					95
            case cssm_ALGID_IntelPlatformRandom =	96
            case cssm_ALGID_UTC =					97
            case cssm_ALGID_HAVAL3 =				98
            case cssm_ALGID_HAVAL4 =				99
            case cssm_ALGID_HAVAL5 =				100
            case cssm_ALGID_TIGER =					101
            case cssm_ALGID_MD5HMAC =				102
            case cssm_ALGID_PKCS5_PBKDF2 = 			103
            case cssm_ALGID_RUNNING_COUNTER =		104
            case cssm_ALGID_LAST =					0x7FFFFFFF
            /* All algorithms IDs that are vendor specific and not
            part of the CSSM specification should be defined relative
            to CSSM_ALGID_VENDOR_DEFINED. */
            case cssm_ALGID_VENDOR_DEFINED =		0x80000000
        }
        fileprivate func kSecAttrKeyTypeAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrKeyType {
                switch v {
                case let .standard(val):
                        dic.setObject(NSNumber(value: val.rawValue as UInt32), forKey: kSecAttrKeyTypeKey as NSCopying)
                case let .custom(val):
                        dic.setObject(NSNumber(value: val as UInt32), forKey: kSecAttrKeyTypeKey as NSCopying)
                }
            }
        }

        open var kSecAttrKeySizeInBits : Int32?  // NSNumber
        fileprivate let kSecAttrKeySizeInBitsKey = "bsiz" 
        fileprivate func kSecAttrKeySizeInBitsAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrKeySizeInBits {
                dic.setObject(NSNumber(value: v as Int32), forKey: kSecAttrKeySizeInBitsKey as NSCopying)
            }
        }
        
        open var kSecAttrEffectiveKeySize : Int32? // NSNumber
        fileprivate let kSecAttrEffectiveKeySizeKey = "esiz" 
        fileprivate func kSecAttrEffectiveKeySizeAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrEffectiveKeySize {
                dic.setObject(NSNumber(value: v as Int32), forKey: kSecAttrEffectiveKeySizeKey as NSCopying)
            }
        }
        
        open var kSecAttrCanEncrypt : Bool? // NSNumber
        fileprivate let kSecAttrCanEncryptKey = "encr" 
        fileprivate func kSecAttrCanEncryptAddToDic(_ dic : NSMutableDictionary) {
            if (kSecAttrCanEncrypt != nil && kSecAttrCanEncrypt!) {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrCanEncryptKey as NSCopying)
            }
        }

        
        open var kSecAttrCanDecrypt : Bool? // NSNumber
        fileprivate let kSecAttrCanDecryptKey = "decr" 
        fileprivate func kSecAttrCanDecryptAddToDic(_ dic : NSMutableDictionary) {
            if kSecAttrCanDecrypt != nil && kSecAttrCanDecrypt! {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrCanDecryptKey as NSCopying)
            }
        }
        
        open var kSecAttrCanDerive : Bool? // NSNumber
        fileprivate let kSecAttrCanDeriveKey = "drve" 
        fileprivate func kSecAttrCanDeriveAddToDic(_ dic : NSMutableDictionary) {
            if kSecAttrCanDerive != nil && kSecAttrCanDerive! {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrCanDeriveKey as NSCopying)
            }
        }

        
        open var kSecAttrCanSign : Bool? // NSNumber
        fileprivate let kSecAttrCanSignKey = "sign" 
        fileprivate func kSecAttrCanSignAddToDic(_ dic : NSMutableDictionary) {
            if (kSecAttrCanSign != nil && kSecAttrCanSign!) {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrCanSignKey as NSCopying)
            }
        }

        
        open var kSecAttrCanVerify : Bool? // NSNumber
        fileprivate let kSecAttrCanVerifyKey = "vrfy" 
        
        
        open var kSecAttrCanWrap : Bool? // NSNumber
        fileprivate let kSecAttrCanWrapKey = "wrap" 
        fileprivate func kSecAttrCanWrapAddToDic(_ dic : NSMutableDictionary) {
            if (kSecAttrCanWrap != nil  && kSecAttrCanWrap!) {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrCanWrapKey as NSCopying)
            }
        }

        
        open var kSecAttrCanUnwrap : Bool? // NSNumber
        fileprivate let kSecAttrCanUnwrapKey = "unwp" 
        fileprivate func kSecAttrCanUnwrapAddToDic(_ dic : NSMutableDictionary) {
            if (kSecAttrCanUnwrap != nil && kSecAttrCanUnwrap!) {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecAttrCanUnwrapKey as NSCopying)
            }
        }

        open var kSecAttrAccessGroup : String?
        fileprivate let kSecAttrAccessGroupKey = "agrp"
         fileprivate func kSecAttrAccessGroupAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecAttrAccessGroup {
                dic.setObject(v, forKey: kSecAttrAccessGroupKey as NSCopying)
            }
        }
        
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Search Attributes
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        
        open var kSecMatchPolicy : SecPolicy?
        fileprivate let kSecMatchPolicyKey = "m_Policy"
         fileprivate func kSecMatchPolicyAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecMatchPolicy {
                dic.setObject(v, forKey: kSecMatchPolicyKey as NSCopying)
            }
        }
        
        open var kSecMatchItemList : NSArray?
        fileprivate let kSecMatchItemListKey = "m_ItemList"
         fileprivate func kSecMatchItemListAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecMatchItemList {
                dic.setObject(v, forKey: kSecMatchItemListKey as NSCopying)
            }
        }
        
        open var kSecMatchSearchList : NSArray?
        fileprivate let kSecMatchSearchListKey = "m_SearchList"
         fileprivate func kSecMatchSearchListAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecMatchSearchList {
                dic.setObject(v, forKey: kSecMatchSearchListKey as NSCopying)
            }
        }
        
        open var kSecMatchIssuers : [Data]?
        fileprivate let kSecMatchIssuersKey = "m_Issuers"
        fileprivate func kSecMatchIssuersAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecMatchIssuers {
                dic.setObject(v, forKey: kSecMatchIssuersKey as NSCopying)
            }
        }
        
        open var kSecMatchEmailAddressIfPresent : String?
        fileprivate let kSecMatchEmailAddressIfPresentKey = "m_EmailAddressIfPresent"
        fileprivate func kSecMatchEmailAddressIfPresentAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecMatchEmailAddressIfPresent {
                dic.setObject(v, forKey: kSecMatchEmailAddressIfPresentKey as NSCopying)
            }
        }
        
        open var kSecMatchSubjectContains : String?
        fileprivate let kSecMatchSubjectContainsKey = "m_SubjectContains"
        fileprivate func kSecMatchSubjectContainsAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecMatchSubjectContains {
                dic.setObject(v, forKey: kSecMatchSubjectContainsKey as NSCopying)
            }
        }
        
        open var kSecMatchCaseInsensitive : Bool = false
        fileprivate let kSecMatchCaseInsensitiveKey = "m_CaseInsensitive"
        fileprivate func kSecMatchCaseInsensitiveAddToDic(_ dic : NSMutableDictionary) {
            if kSecMatchCaseInsensitive {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecMatchCaseInsensitiveKey as NSCopying)
            }
        }

        
        open var kSecMatchTrustedOnly : Bool = false
        fileprivate let kSecMatchTrustedOnlyKey = "m_TrustedOnly"
        fileprivate func kSecMatchTrustedOnlyAddToDic(_ dic : NSMutableDictionary) {
            if kSecMatchTrustedOnly {
                dic.setObject(NSNumber(value: true as Bool), forKey: kSecMatchTrustedOnlyKey as NSCopying)
            }
        }

        
        open var kSecMatchValidOnDate : Date?
        fileprivate let kSecMatchValidOnDateKey = "m_ValidOnDate"
        fileprivate func kSecMatchValidOnDateAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecMatchValidOnDate {
                dic.setObject(v, forKey: kSecMatchValidOnDateKey as NSCopying)
            }
        }
        
        
        open var kSecMatchLimit : KSecMatchLimitValue?
        fileprivate let kSecMatchLimitKey = "m_Limit"
        fileprivate let kSecMatchLimitOneKey = "m_LimitOne"
        fileprivate let kSecMatchLimitAllKey = "m_LimitAll"
        public enum KSecMatchLimitValue {
            case kSecMatchLimitOne
            case kSecMatchLimitAll
            case limit(Int)
        }
        fileprivate func kSecMatchLimitAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecMatchLimit {
                switch v {
                case .kSecMatchLimitOne:
                    dic.setObject(kSecMatchLimitOneKey, forKey: kSecMatchLimitKey as NSCopying)
                    
                case .kSecMatchLimitAll:
                    dic.setObject(kSecMatchLimitAllKey, forKey: kSecMatchLimitKey as NSCopying)
                    
                case let .limit(val):
                    dic.setObject(NSNumber(value: val as Int), forKey: kSecMatchLimitKey as NSCopying)
   
                }
            }
        }
        
 
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Item List
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        
        open var kSecUseItemList : KSecUseItemListValue?
        fileprivate let kSecUseItemListKey = "u_ItemList"
        public enum KSecUseItemListValue {
            //case KeychainItems([SecKeychainItemRef])
            case keys([SecKey])
            case certificates([SecCertificate])
            case identities([SecIdentity])
            case persistentItems([Data])
        }
        fileprivate func kSecUseItemListAddToDic(_ dic : NSMutableDictionary) {
            if let v = kSecUseItemList {
                switch v {
                case let .keys(val):
                    dic.setObject(val, forKey: kSecUseItemListKey as NSCopying)
                    
                case let .certificates(val):
                    dic.setObject(val, forKey: kSecUseItemListKey as NSCopying)
                    
                case let .identities(val):
                    dic.setObject(val, forKey: kSecUseItemListKey as NSCopying)
                
                case let .persistentItems(val):
                    dic.setObject(val, forKey: kSecUseItemListKey as NSCopying)
                }
            }
        }
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Helper functions
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
     
        open func toNSDictionary() -> NSDictionary
        {
            let dic = NSMutableDictionary()
            
            let addFunctions = [
                kSecClassAddToDic,
                kSecReturnDataAddToDic,
                kSecReturnAttributesAddToDic,
                kSecReturnRefAddToDic,
                kSecReturnPersistentRefAddToDic,
                kSecValueDataAddToDic,
                kSecValueRefAddToDic,
                kSecValuePersistentRefAddToDic,
                kSecAttrAccessibleAddToDic,
                kSecAttrCreationDateAddToDic,
                kSecAttrModificationDateAddToDic,
                kSecAttrDescriptionAddToDic,
                kSecAttrCommentAddToDic,
                kSecAttrCreatorAddToDic,
                kSecAttrTypeAddToDic,
                kSecAttrLabelAddToDic,
                kSecAttrIsInvisibleAddToDic,
                kSecAttrIsNegativeAddToDic,
                kSecAttrAccountAddToDic,
                kSecAttrServiceAddToDic,
                kSecAttrGenericAddToDic,
                kSecAttrSecurityDomainAddToDic,
                kSecAttrServerAddToDic,
                kSecAttrProtocolAddToDic,
                kSecAttrAuthenticationTypeAddToDic,
                kSecAttrPortAddToDic,
                kSecAttrPathAddToDic,
                kSecAttrSubjectAddToDic,
                kSecAttrIssuerAddToDic,
                kSecAttrSerialNumberAddToDic,
                kSecAttrSubjectKeyIDAddToDic,
                kSecAttrPublicKeyHashAddToDic,
                kSecAttrCertificateTypeAddToDic,
                kSecAttrCertificateEncodingAddToDic,
                kSecAttrKeyClassAddToDic,
                kSecAttrApplicationLabelAddToDic,
                kSecAttrIsPermanentAddToDic,
                kSecAttrApplicationTagAddToDic,
                kSecAttrKeyTypeAddToDic,
                kSecAttrKeySizeInBitsAddToDic,
                kSecAttrEffectiveKeySizeAddToDic,
                kSecAttrCanEncryptAddToDic,
                kSecAttrCanDecryptAddToDic,
                kSecAttrCanDeriveAddToDic,
                kSecAttrCanSignAddToDic,
                kSecAttrCanWrapAddToDic,
                kSecAttrCanUnwrapAddToDic,
                kSecAttrAccessGroupAddToDic,
                kSecMatchPolicyAddToDic,
                kSecMatchItemListAddToDic,
                kSecMatchSearchListAddToDic,
                kSecMatchIssuersAddToDic,
                kSecMatchEmailAddressIfPresentAddToDic,
                kSecMatchSubjectContainsAddToDic,
                kSecMatchCaseInsensitiveAddToDic,
                kSecMatchTrustedOnlyAddToDic,
                kSecMatchValidOnDateAddToDic,
                kSecMatchLimitAddToDic,
                kSecUseItemListAddToDic]
            
            
            for f in addFunctions {
                f(dic)
            }

            return dic
        }
    }
    
    /**
    A Swift wrapper of OSStatus SecItemAdd(CFDictionaryRef attributes,CFTypeRef *result) C function.
    
    - parameter query: An object wrapping a CFDictionaryRef with attributes
    - returns: A pair containing the result code and an NSObject that was returned in the result parameter of SecItemAdd call.
    
    */
    
    open class func secItemAdd(query : Query) -> (status: ResultCode, result: NSObject?)
    {
        let resultAndStatus = CXKeychainHelper.secItemAddCaller(query.toNSDictionary() as! [AnyHashable: Any])
        let status = ResultCode.fromRaw((resultAndStatus?.status)!)
        return (status: status, result: resultAndStatus!.result)
    }
    
    /**
    A Swift wrapper of OSStatus SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) C function.
    
    - parameter query: An object wrapping a CFDictionaryRef with query
    - returns: A pair containing the result code and an NSObject that was returned in the result parameter of SecItemCopyMatching call.
    
    */
    open class func secItemCopyMatching(query : Query) -> (status: ResultCode, result: NSObject?)
    {
        let dic : NSDictionary = query.toNSDictionary()
        let resultAndStatus = CXKeychainHelper.secItemCopy(matchingCaller: dic as! [AnyHashable: Any])
        return (status: ResultCode.fromRaw(resultAndStatus!.status), result: resultAndStatus!.result)
    }
    
    /**
    A Swift wrapper of OSStatus SecItemDelete(CFDictionaryRef query) C function.
    
    - parameter query: An object wrapping a CFDictionaryRef with query
    - returns: A result code.
    
    */
    
    open class func secItemDelete(query : Query) -> ResultCode
    {
        let statusRaw = SecItemDelete(query.toNSDictionary())
        let status = ResultCode.fromRaw(statusRaw)
        return status
    }

    /**
    A Swift wrapper of OSStatus SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) C function.
    
    - parameter query: An object wrapping a CFDictionaryRef with query
    - parameter attributesToUpdate: An object wrapping a CFDictionaryRef with attributesToUpdate
    - returns: A result code.
    
    */
    open class func secItemUpdate(query : Query, attributesToUpdate : Query) -> ResultCode
    {
        let statusRaw = SecItemUpdate(query.toNSDictionary(),attributesToUpdate.toNSDictionary())
        let status = ResultCode.fromRaw(statusRaw)
        return status
    }
    

}
