//
//  Created by Leslie Helou on 9/22/22
//


import Foundation
import os.log
import Security

//log stream --info --predicate 'subsystem == "<app.bundle.id>"'
//log stream --info --predicate 'subsystem == "<app.bundle.id>" AND category == "retrieveCredentials"'

@MainActor let kSecAttrAccountString          = NSString(format: kSecAttrAccount)
@MainActor let kSecValueDataString            = NSString(format: kSecValueData)
@MainActor let kSecClassGenericPasswordString = NSString(format: kSecClassGenericPassword)
let prefix                                    = Bundle.main.infoDictionary?["CFBundleExecutable"] as? String ?? "unknown"
@MainActor var sharedPrefix                   = ""
@MainActor var accessGroup                    = ""

@MainActor public final class MySimpleKeychainHelper {
    
    @MainActor public static let shared = MySimpleKeychainHelper()
    /*@MainActor public*/private init() {
        Task {
            let teamId = await fetchTeamId()
            configureAccessGroup(with: teamId)
        }
    }
    
    @MainActor private func configureAccessGroup(with teamId: String) {
        Logger.teamId.info("found team id: \(teamId, privacy: .public)")
        accessGroup = "\(teamId).jamfie.Shared\(teamId == "PS2F6S478M" ? "JPMA" : "JSK")"
        sharedPrefix = teamId == "PS2F6S478M" ? "JPMA" : "JSK"
        Logger.teamId.info("access group: \(accessGroup, privacy: .public)")
        Logger.teamId.info("sharedPrefix: \(sharedPrefix, privacy: .public)")
    }
    
    @MainActor public func save(service: String, account: String, credential: String, useApiClient: Bool, comment: String = "") async -> String {
        
        var returnMessage = "keychain save process completed successfully"
        
            if !service.isEmpty && !account.isEmpty && !credential.isEmpty {
                    
                var theService = service.lowercased().fqdnFromUrl
            
                if useApiClient {
                    theService = "apiClient-" + theService
                }
                
                let keychainItemName = sharedPrefix + "-" + theService
                
                Logger.saveCredentials.info("theService: \(theService, privacy: .public)")
                Logger.saveCredentials.info("keychain item \(keychainItemName, privacy: .public) for account \(account, privacy: .public)")

                if let password = credential.data(using: String.Encoding.utf8) {

                    var keychainQuery: [String: Any] = [kSecClass as String: kSecClassGenericPasswordString,
                                                        kSecAttrService as String: keychainItemName,
                                                        kSecAttrAccessGroup as String: accessGroup,
                                                        kSecUseDataProtectionKeychain as String: true,
                                                        kSecAttrComment as String: comment,
                                                        kSecAttrAccount as String: account.lowercased(),
                                                        kSecValueData as String: password]
                    
                    // see if credentials already exist for server
                    //                    print("[save] for for keychain item: \(service) for account: \(account)")
                    let accountCheck = await retrieve(service: service, account: account, useApiClient: useApiClient)
//                        print("[save] service: \(service)")
//                        print("[save] matches found: \(accountCheck.count)")
//                        print("[save] matches: \(accountCheck)")
                    if accountCheck[account] == nil {
                        // try to add new credentials
                        Logger.saveCredentials.info("adding new keychain item \(keychainItemName, privacy: .public) for account \(account, privacy: .public)")

                        let addStatus = SecItemAdd(keychainQuery as CFDictionary, nil)
                        if (addStatus != errSecSuccess) {
                            if let addErr = SecCopyErrorMessageString(addStatus, nil) {
                                Logger.saveCredentials.info("write failed for service \(keychainItemName, privacy: .public), account \(account, privacy: .public): \(addErr, privacy: .public)")
                            }
                            returnMessage = "keychain save process was unsuccessful"
                        } else {
                           Logger.saveCredentials.info("keychain item added")
                        }
                    } else {
                        // credentials already exist, try to update
                       Logger.saveCredentials.info("see if keychain item \(keychainItemName, privacy: .public) for account \(account, privacy: .public) needs updating")
                        keychainQuery = [kSecClass as String: kSecClassGenericPasswordString,
                                         kSecAttrService as String: keychainItemName,
                                         kSecAttrAccessGroup as String: accessGroup,
                                         kSecAttrAccount as String: account.lowercased(),
                                         kSecUseDataProtectionKeychain as String: true,
                                         kSecMatchLimit as String: kSecMatchLimitOne,
                                         kSecReturnAttributes as String: true]
                        if credential != accountCheck[account] {
                            let updateStatus = SecItemUpdate(keychainQuery as CFDictionary, [kSecValueDataString:password] as [NSString : Any] as CFDictionary)
                            if (updateStatus != errSecSuccess) {
                                
                               Logger.saveCredentials.info("keychain item for service \(service, privacy: .public), account \(account, privacy: .public), failed to update.")
                                returnMessage = "keychain save process was unsuccessful"
//
                            } else {
//                                    print("[addStatus] keychain item for service \(service), account \(account), has been updated.")
                               Logger.saveCredentials.info("keychain item for service \(service, privacy: .public), account \(account, privacy: .public), has been updated.")
                            }
                        } else {
                            Logger.saveCredentials.info("keychain item for service \(service, privacy: .public), account \(account, privacy: .public), is current.")
                            returnMessage = "keychain item is current"
                        }
                    }
                    //                    }
                } else {
                    Logger.saveCredentials.info("failed to set password for \(keychainItemName, privacy: .public), account \(account, privacy: .public)")
                    returnMessage = "keychain save process was unsuccessful"
                }
            } else {
                returnMessage = "keychain save process was unsuccessful"
            }
            
            print("[Credentials.save] returnMessage:\(returnMessage)")
        return returnMessage
    }
    
    @MainActor public func retrieve(service: String, account: String = "", useApiClient: Bool) async -> [String:String] {
       Logger.retrieveCredentials.info("fetch credentials for service: \(service, privacy: .public), account: \(account, privacy: .public)")
        //        print("[credentials.retrieve] service passed: \(service)")
        var keychainResult = [String:String]()
        var theService     = service.lowercased().fqdnFromUrl

        Logger.retrieveCredentials.info("useApiClient: \(useApiClient, privacy: .public)")
        
        if useApiClient {
            theService = "apiClient-" + theService
        }
        
        let keychainItemName = sharedPrefix + "-" + theService
        
        Logger.retrieveCredentials.info("keychainItemName: \(keychainItemName, privacy: .public)")

        // look for common keychain item
        keychainResult = itemLookup(service: keychainItemName)
        
        if keychainResult.count > 1 && !account.isEmpty {
            
            for (username, password) in keychainResult {
                if username.lowercased() == account.lowercased() {
                    Logger.retrieveCredentials.info("found password/secret for: \(account, privacy: .public)")
                    return [username:password]
                }
            }
        }
        
        return keychainResult
    }
    
    @MainActor func itemLookup(service: String) -> [String:String] {
        var userPassDict = [String:String]()
//        print("[credentials.itemLookup] keychainName: \(service)")
        let keychainQuery: [String: Any] = [kSecClass as String: kSecClassGenericPasswordString,
                                            kSecAttrService as String: service,
                                            kSecAttrAccessGroup as String: accessGroup,
                                            kSecUseDataProtectionKeychain as String: true,
                                            kSecMatchLimit as String: kSecMatchLimitAll,
                                            kSecReturnAttributes as String: true,
                                            kSecReturnData as String: true] // new

        var items_ref: CFTypeRef?
        
        let status = SecItemCopyMatching(keychainQuery as CFDictionary, &items_ref)
        guard status != errSecItemNotFound else {
            Logger.credentialsLookup.info("keychain item, \(service, privacy: .public), was not found")
            return [:]
            
        }
        guard status == errSecSuccess else { return [:] }
        
        guard let items = items_ref as? [[String: Any]] else {
            Logger.credentialsLookup.info("unable to read keychain item: \(service, privacy: .public)")
            return [:]
        }
        for item in items {
            if let account = item[kSecAttrAccount as String] as? String, let passwordData = item[kSecValueData as String] as? Data {
                let password = String(data: passwordData, encoding: String.Encoding.utf8)
                userPassDict[account] = password ?? ""
            }
        }

        Logger.credentialsLookup.info("keychain item count: \(userPassDict.count, privacy: .public) for \(service, privacy: .public)")
        return userPassDict
    }
    
    @MainActor func delete(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        return status == errSecSuccess
    }
    
    @MainActor func fetchTeamId() async -> String {
        let defaultTeamId = "PS2F6S478M"
        
        // Locate the embedded.provisionprofile file in the app bundle
        guard let fileURL = Bundle.main.url(forResource: "embedded", withExtension: "provisionprofile", subdirectory: "Contents") else {
            Logger.teamId.error("embedded.provisionprofile not found")
            return defaultTeamId
        }
        
        do {
            // Read the contents of the provision profile
            let data = try Data(contentsOf: fileURL)
            
            // Deserialize the plist into a dictionary
            let propertyList = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            
            // The result is a dictionary or array depending on the plist structure
            guard let provisionProfile = propertyList as? [String: Any] else {
                Logger.teamId.error("The provision profile is not in the expected format")
                return defaultTeamId
            }
            
            if let entitlements = provisionProfile["Entitlements"] as? [String : Any], let teamId = entitlements["com.apple.developer.team-identifier"] as? String {
                Logger.teamId.info("Found team ID: \(teamId, privacy: .public)")
                return teamId
            }
            
            return defaultTeamId
        } catch {
            Logger.teamId.error("Error reading or parsing the embedded.provisionprofile: \(error, privacy: .public)")
            return defaultTeamId
        }
    }
}

private extension Logger {
    private static let subsystem = Bundle.main.bundleIdentifier!
    
    static let teamId              = Logger(subsystem: subsystem, category: "teamId")
    static let saveCredentials     = Logger(subsystem: subsystem, category: "saveCredentials")
    static let retrieveCredentials = Logger(subsystem: subsystem, category: "retrieveCredentials")
    static let credentialsLookup   = Logger(subsystem: subsystem, category: "credentialsLookup")
}

private extension String {
    var baseUrl: String {
        get {
            var fqdn = ""
            let nameArray = self.components(separatedBy: "/")
            if nameArray.count > 2 {
                fqdn = nameArray[2]
            } else {
                fqdn =  self
            }
            return "\(nameArray[0])//\(fqdn)"
        }
    }
    var fqdnFromUrl: String {
        get {
            var fqdn = ""
            let nameArray = self.components(separatedBy: "/")
            if nameArray.count > 2 {
                fqdn = nameArray[2]
            } else {
                fqdn =  nameArray[0]
            }
            if fqdn.contains(":") {
                let fqdnArray = fqdn.components(separatedBy: ":")
                fqdn = fqdnArray[0]
            }
            return fqdn
        }
    }
    func occurrencesOf(string: String) -> Int {
        return self.components(separatedBy:string).count
    }

}
