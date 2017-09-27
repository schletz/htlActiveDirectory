/*jslint node white this */

"use strict";
var ActiveDirectory = require('activedirectory');

/**
 * Führt Abfragen im Active Directory von htl-wien5.schule durch.
 * @class
 * @example
 * var htlAd = require("./htl_active_directory.class");
 */
function HtlActiveDirectory() {
    this.adInstance = null;
}

/**
 * Prüft, ob der übergebene Benutzernamen und das Passwort korrekt sind, indem eine 
 * Authentifizierung im AD versucht wird. 
 * 
 * @param {string} username Der Username ohne Prefixe wie Domainnamen (einfach in der Form ABC12345 
 * übergeben)
 * @param {string} password Das Passwort im Klartext.
 * @param {function()} onSuccess Wird aufgerufen, wenn das Login erfolgreich war.
 * @param {function(message:string, innerException:object)} onError Wird aufgerufen, wenn das Login
 * nicht erfolgreich war. message kann "INVALID_ARGUMENTS", "LOGIN_FAILED" oder "SERVER_ERROR" sein.
 * @example
 * htlAd.login(sentUsername, sentPassword,
 *    // onSuccess bei Login
 *    function () {
 *        console.log("Login OK.");
 *    },
 *    // onError bei Login 
 *   function (message, innerMessage) {
 *       console.log(message, innerMessage);
 *   }
 */
HtlActiveDirectory.prototype.login = function (username, password, onSuccess, onError) {
    onSuccess = typeof onSuccess === "function" ? onSuccess : function () { return; };
    onError = typeof onSuccess === "function" ? onError : function () { return; };
    if (typeof username !== "string" || typeof password !== "string") {
        return onError("INVALID_ARGUMENTS");
    }

    this.adInstance = new ActiveDirectory({
        url: 'ldaps://ldap.spengergasse.at',
        baseDN: 'DC=htl-wien5,DC=schule',
        /* Wichtig für LDAPS, da wir unbekannten Root CAs (der Domäne) vertrauen müssen */
        tlsOptions: {requestCert: true, rejectUnauthorized: false},
        /* Diese Daten werden für getGroupMembership verwendet. Beim Usernamen muss immer 
         * @htl-wien5.schule für ein ldap bind angehängt werden. */
        username: username + "@htl-wien5.schule",
        password: password
    });

    /* Wir prüfen die Logindaten schon vorher, somit können wir das Login und das Suchen der
     * Gruppenmitgliedschaft trennen */
    this.adInstance.authenticate(username + "@htl-wien5.schule", password, function (err, auth) {
        if (err !== null) {
            if (err.toString().indexOf("InvalidCredentialsError") !== -1) {
                return onError("LOGIN_FAILED");
            }
            else {
                return onError("SERVER_ERROR", err);
            }
        }
        if (auth) {
            return onSuccess();
        }
    });
};


/**
 * Liefert alle Gruppen, in der der übergebene User Mitglied ist. Dieser User muss nicht der eigene
 * User sein. Eine Suche ohne Login (anonym) ist jedoch durch die Rechteeinstellungen im AD nicht
 * möglich. 
 * Meistens wird der User seine eigenen Gruppenmitgliedschaften heraussuchen, d. h. ein login wird
 * mit den übermittelten Userdaten durchgeführt. Danach werden von diesem User die Gruppen 
 * herausgesucht.
 * 
 * @param {string} username
 * @param {function(string[])} onSuccess Liefert ein Array mit allen Gruppenmitgliedschaften.
 * @param {function(string)} onError Liefert "NOT_CONNECTED", "SERVER_ERROR" oder "USER_UNKNOWN"
 * @example
 * htlAd.getUsersOfGroup("AlleLehrende",
 *            // onSuccess
 *            function (userlist) {
 *                console.log("Members von AlleLehrende", userlist);
 *           },
 *            // onError
 *            function (message) {
 *                console.log(message);
 *            });
 */
HtlActiveDirectory.prototype.getGroupMembership = function (username, onSuccess, onError) {
    onSuccess = typeof onSuccess === "function" ? onSuccess : function () { return; };
    onError = typeof onSuccess === "function" ? onError : function () { return; };

    /* Vorher wurde kein Login gemacht. */
    if (this.adInstance === null) {
        return onError("NOT_CONNECTED");
    }

    this.adInstance.getGroupMembershipForUser(username, function (err, groups) {
        var groupArray = [];
        if (err) {
            return onError("SERVER_ERROR", err);
        }
        if (groups) {
            /* Die Gruppennamen lauten cn=....,ou=,..,ou=... Wir möchten nur den cn (common name) */
            groups.forEach(function (val) {
                try {
                    var matches = val.dn.match(/cn=([^,]+)/i);
                    if (matches !== null && typeof matches[1] === "string") {
                        groupArray.push(matches[1]);
                    }
                }
                catch (e) { return;  }
            });
            return onSuccess(groupArray);
        }
        else {
            return onError("USER_UNKNOWN");
        }
    });
};

/**
 * Listet alle User, die Mitglied der angegebenen Gruppe sind.
 * 
 * @param {string} groupName Gruppenname ohne cn und ou.
 * @param {function(json[])} onSuccess JSON Array mit allen Details zu den Userobjekten. Am 
 * interessantesten ist das dn Property, es gibt den eindeutigen Usernamen an.
 * @param {function(string)} onError Liefert "SERVER_ERROR" oder "GROUP_UNKNOWN"
 */
HtlActiveDirectory.prototype.getUsersOfGroup = function (groupName, onSuccess, onError) {
    onSuccess = typeof onSuccess === "function" ? onSuccess : function () { return; };
    onError = typeof onSuccess === "function" ? onError : function () { return; };
    if (typeof groupName !== "string") {
        return onError("INVALID_ARGUMENTS");
    }

    this.adInstance.getUsersForGroup(groupName, function (err, users) {
        if (err) {
            return onError("SERVER_ERROR", err);
        }
        if (users) {
            onSuccess(users);
        }
        else {
            return onError("GROUP_UNKNOWN");
        }
    });
};

module.exports = new HtlActiveDirectory();
