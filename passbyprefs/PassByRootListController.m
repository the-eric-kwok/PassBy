#include <notify.h>
#include <objc/runtime.h>

#include "PassByRootListController.h"
#include "../crypto.h"

#define PLIST_PATH      "/var/mobile/Library/Preferences/com.giorgioiavicoli.passby.plist"
#define WIFI_PLIST_PATH "/var/mobile/Library/Preferences/com.giorgioiavicoli.passbynets.plist"
#define BT_PLIST_PATH   "/var/mobile/Library/Preferences/com.giorgioiavicoli.passbybt.plist"

void openURL(NSURL * url)
{
    if ([UIApplication respondsToSelector:@selector(openURL:options:completionHandler:)]) {
        [   [UIApplication sharedApplication]
            openURL:url options:@{} completionHandler:nil
        ];
    } else {
        [   [UIApplication sharedApplication]
            openURL:url
        ];
    }
}

// Localizes UI strings through the preference bundle's language tables;
// the English source text is the lookup key, so missing entries fall back to it.
static NSString * PBLoc(PSListController * controller, NSString * key)
{
    return [[controller bundle] localizedStringForKey:key value:key table:nil];
}

@implementation PassByRootListController

- (NSArray *)specifiers
{
	if (!_specifiers)
		_specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier*)specifier
{
    NSDictionary * settings = [NSDictionary dictionaryWithContentsOfFile:@PLIST_PATH];
    return settings[[specifier propertyForKey:@"key"]] ?:[specifier properties][@"default"];
}

- (void)savePreferencesDict:(NSDictionary*)settings
{
    [settings writeToFile:@(PLIST_PATH) atomically:YES];
    notify_post("com.giorgioiavicoli.passby/reload");
    [self reloadSpecifiers];
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier*)specifier
{
    NSMutableDictionary * settings =
        [NSMutableDictionary dictionaryWithContentsOfFile:@PLIST_PATH]
        ?:[NSMutableDictionary dictionary];

    NSString * key = [specifier propertyForKey:@"key"];

    if ([key isEqualToString:@"savePasscode"]
    && [value boolValue] == NO
    ) {
        [settings removeObjectForKey:@"passcode"];
        settings[key] = value;
        [self savePreferencesDict:settings];
        return;
    }

    if ([key isEqualToString:@"disableFromTime"]
    || [key isEqualToString:@"disableToTime"]
    ) {
        int len = [value length];
        if (len) {
            if (len <= 2) {
                value = [value mutableCopy];
                [value appendString:@":00"];
            } else if (len <= 4 && [value characterAtIndex:len-3] != ':') {
                value = [value mutableCopy];
                [value insertString:@":" atIndex:len-2];
            }
        }
        settings[key] = value;
        [self savePreferencesDict:settings];
        return;
    }

    if ([key isEqualToString:@"watchAutoUnlock"]
    && [value boolValue] == YES
    ) {
        UIAlertController* alertController = [UIAlertController
            alertControllerWithTitle:PBLoc(self, @"Security risk")
            message:PBLoc(self, @"In this version, enabling this will let your phone auto-unlock"
                " even when the watch itself is locked (but still in proximity).")
            preferredStyle:UIAlertControllerStyleAlert
        ];
        [alertController addAction: [UIAlertAction actionWithTitle:PBLoc(self, @"Enable")
            style:UIAlertActionStyleDestructive
            handler:^(UIAlertAction * action) {
                settings[key] = value;
                [self savePreferencesDict:settings];
            }
        ]];
        [alertController addAction: [UIAlertAction actionWithTitle:PBLoc(self, @"Don't enable")
            style:UIAlertActionStyleCancel
            handler:^(UIAlertAction * action) {
                [self reloadSpecifiers];
            }
        ]];
        [self presentViewController:alertController animated:YES completion:nil];
        return;
    }

    settings[key] = value;
    [self savePreferencesDict:settings];
}


-(void)sourceCode:(id)arg1
{
    openURL([NSURL URLWithString:@"https://github.com/the-eric-kwok/PassBy"]);
}

-(void)sendFeedback:(id)arg1
{
    openURL([NSURL URLWithString:@"https://github.com/the-eric-kwok/PassBy/issues"]);
}

-(void)resetSettings:(id)arg1
{
    [@{} writeToFile:@PLIST_PATH        atomically:YES];
    [@{} writeToFile:@WIFI_PLIST_PATH   atomically:YES];
    [@{} writeToFile:@BT_PLIST_PATH     atomically:YES];
	notify_post("com.giorgioiavicoli.passby/reload");
    [self reloadSpecifiers];
}

@end



@implementation PassByWiFiListController

NSDictionary * _networksDict;

- (NSArray *)specifiers
{
	if (!_specifiers) {
        NSMutableArray * specifiers = [NSMutableArray new];
        NSMutableDictionary* networksDict = [NSMutableDictionary new];
        NSDictionary * networksList =
            [NSDictionary dictionaryWithContentsOfFile:@WIFI_PLIST_PATH]
            ?: [NSDictionary dictionary];

        WiFiManagerRef manager = WiFiManagerClientCreate(kCFAllocatorDefault, 0);
        if (manager) {
            NSArray * networks = (NSArray *) CFBridgingRelease(WiFiManagerClientCopyNetworks(manager));
            for (id network in networks) {
                NSString* name = (NSString *) CFBridgingRelease(WiFiNetworkGetSSID((__bridge WiFiNetworkRef)network));

                if (name) {
                    PSSpecifier * specifier =
                        [ PSSpecifier
                            preferenceSpecifierNamed:name
                            target:self
                            set:@selector(setPreferenceValue:specifier:)
                            get:@selector(readPreferenceValue:)
                            detail: nil
                            cell:PSSwitchCell
                            edit: nil
                        ];
                    [specifier setProperty:name forKey:@"key"];
                    [specifier setProperty:@(TRUE) forKey:@"enabled"];
                    [specifier
                        setProperty:networksList[SHA1(name)]?:@(0)
                        forKey:@"default"
                    ];
                    [specifiers addObject:specifier];

                    [networksDict
                        setObject:@{
                            @"isHidden":@(WiFiNetworkIsHidden((__bridge WiFiNetworkRef)network)),
                            @"isProtected":@(WiFiNetworkIsWEP((__bridge WiFiNetworkRef)network)
                                ||  WiFiNetworkIsWPA((__bridge WiFiNetworkRef)network)
                                ||  WiFiNetworkIsEAP((__bridge WiFiNetworkRef)network)
                            )
                        }
                        forKey:name
                    ];
                }
            }
            CFRelease(manager);
        }
        _specifiers = specifiers;
        _networksDict = networksDict;
    }

    return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier*)specifier
{
    NSString * key = [specifier propertyForKey:@"key"];
    NSDictionary * settings = [NSDictionary dictionaryWithContentsOfFile:@WIFI_PLIST_PATH];
    return settings[key] ?:[specifier properties][@"default"];
}

- (void)realSetPreferenceValue:(NSString*)name value:(id)value
{
    NSMutableDictionary * settings =
        [NSMutableDictionary dictionaryWithContentsOfFile:@WIFI_PLIST_PATH]
        ?:[NSMutableDictionary dictionary];
    settings[SHA1(name)] = value;
    [settings writeToFile:@(WIFI_PLIST_PATH) atomically:YES];
    notify_post("com.giorgioiavicoli.passby/wifi");
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier*)specifier
{
    NSString * name = [specifier propertyForKey:@"key"];
    NSDictionary* networkProperties = _networksDict[name];

    if (![value boolValue] || networkProperties[@"isProtected"]) {
        [self realSetPreferenceValue:name value:value];
    } else {
        NSString* message = PBLoc(self, @"Adding this open network to the whitelist will make your device vulnerable."
            "\nDO NOT enable *this* network if you are using the option \"Even when connected while locked\".");
        if (networkProperties[@"isHidden"]) {
            message = [message stringByAppendingString:PBLoc(self, @"\nThe selected network is also of the \"hidden\" kind."
                " Please, really do not combine this with the aforementioned option"
                " unless you know *exactly* what yuo are doing.")];
        }

        UIAlertController * alert =
            [UIAlertController
                alertControllerWithTitle:PBLoc(self, @"Unprotected network")
                message:[message stringByAppendingString:[networkProperties description]]
                preferredStyle: UIAlertControllerStyleAlert
            ];

        [alert addAction:
            [UIAlertAction
                actionWithTitle:PBLoc(self, @"Proceed anyway")
                style:UIAlertActionStyleDestructive
                handler:
                    ^(UIAlertAction * action)
                    { [self realSetPreferenceValue:name value:value]; }
            ]
        ];

        [alert addAction:
            [UIAlertAction
                actionWithTitle:PBLoc(self, @"Cancel")
                style:UIAlertActionStyleCancel
                handler:
                    ^(UIAlertAction * action)
                    { [self reloadSpecifiers]; }
            ]
        ];

        [self presentViewController:alert animated:YES completion:nil];
    }
}

@end


@implementation PassByBTListController

- (NSArray *)specifiers
{
	if (!_specifiers) {
        NSMutableArray * specifiers = [NSMutableArray new];

        NSDictionary * bluetoothList =
            [NSDictionary dictionaryWithContentsOfFile:@BT_PLIST_PATH]
            ?: [NSDictionary dictionary];

        BluetoothManager *  bluetoothManager    = [BluetoothManager sharedInstance];
        NSArray          *  pairedDevices       = [bluetoothManager pairedDevices];

        if ([pairedDevices count]) {
            for (BluetoothDevice * bluetoothDevice in pairedDevices) {
                NSString * name = [bluetoothDevice name];

                if (name) {
                    PSSpecifier * specifier =
                        [ PSSpecifier
                            preferenceSpecifierNamed:name
                            target:self
                            set:@selector(setPreferenceValue:specifier:)
                            get:@selector(readPreferenceValue:)
                            detail:Nil
                            cell:PSSwitchCell
                            edit:Nil
                        ];
                    [specifier setProperty:[NSString stringWithString:name] forKey:@"key"];
                    [specifier setProperty:@(TRUE) forKey:@"enabled"];
                    [specifier
                        setProperty:bluetoothList[SHA1(name)]?:@(NO)
                        forKey:@"default"
                    ];
                    [specifiers addObject:specifier];
                }
            }
        }

        _specifiers = specifiers;
    }

    return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier*)specifier
{
    NSString * key = [specifier propertyForKey:@"key"];
    NSDictionary * settings = [NSDictionary dictionaryWithContentsOfFile:@BT_PLIST_PATH];
    return settings[key] ?:[specifier properties][@"default"];
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier*)specifier
{
    NSMutableDictionary * settings =
        [NSMutableDictionary dictionaryWithContentsOfFile:@BT_PLIST_PATH]
        ?:[NSMutableDictionary dictionary];
    settings[SHA1([specifier propertyForKey:@"key"])] = value;
    [settings writeToFile:@(BT_PLIST_PATH) atomically:YES];
    notify_post("com.giorgioiavicoli.passby/bt");
}
@end

@implementation PassByMagicPasscodeListController
- (NSArray *)specifiers
{
	if (!_specifiers)
		_specifiers = [self loadSpecifiersFromPlistName:@"MagicPasscode" target:self];
	return _specifiers;
}

- (id)readPreferenceValue:(PSSpecifier*)specifier
{
    NSDictionary * settings = [NSDictionary dictionaryWithContentsOfFile:@PLIST_PATH];
    return settings[[specifier propertyForKey:@"key"]] ?:[specifier properties][@"default"];
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier*)specifier
{
    NSMutableDictionary * settings =
        [NSMutableDictionary dictionaryWithContentsOfFile:@PLIST_PATH]
        ?:[NSMutableDictionary dictionary];

    settings[[specifier propertyForKey:@"key"]] = value;
    [settings writeToFile:@(PLIST_PATH) atomically:YES];
    notify_post("com.giorgioiavicoli.passby/reload");
}
@end
