define(["jquery"],
    function ($) {
        "use strict";

        function buildQueryParameters(array) {
            let queryStringArray = [];

            array.forEach(item => {
                if (item.s !== undefined) {
                    queryStringArray.push(item.p + "=" + item.s);
                }
            });

            return queryStringArray.join("&");
        }

        function handleAsync(promise, request) {
            return promise.then(function (response) {
                if (response.success === true) {
                    return request.dataFunc(response);
                } else {
                    console.error({ errorMessage: response.errorMessage, url: request.url });
                    throw `${request.errorMessage} - ${response.errorMessage}`;
                }
            }).catch(function (jqXHR, textStatus, errorThrown) {
                if (jqXHR.status === 401) {
                    //throw "Session has expired";
                    window.location = "home/logout";
                    return;
                }
                console.error({ jqXHR: jqXHR, textStatus: textStatus, errorThrown: errorThrown, url: request.url });
                throw jqXHR.responseText ?? jqXHR;
            });
        }

        function postAsync(request) {
            const token = window.sessionStorage.getItem("master-password-token") ?? "";
            const promise = $.ajax({
                url: request.url,
                method: "POST",
                contentType: "application/json",
                dataType: "json",
                data: JSON.stringify(request.dataObj),
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            });
            return handleAsync(promise, request);
        }

        function getAsync(request) {
            const token = window.sessionStorage.getItem("master-password-token") ?? "";
            const promise = $.ajax({
                url: request.url,
                method: "GET",
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            });
            return handleAsync(promise, request);
        }

        function deleteAsync(request) {
            const token = window.sessionStorage.getItem("master-password-token");
            const promise = $.ajax({
                url: request.url,
                method: "DELETE",
                contentType: "application/json",
                dataType: "json",
                data: JSON.stringify(request.dataObj),
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            });
            return handleAsync(promise, request);
        }

        function patchAsync(request) {
            const token = window.sessionStorage.getItem("master-password-token");
            const promise = $.ajax({
                url: request.url,
                method: "PATCH",
                contentType: "application/json",
                dataType: "json",
                data: JSON.stringify(request.dataObj),
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            });
            return handleAsync(promise, request);
        }

        return {
            checkSessionAsync: function () {
                return getAsync({
                    url: "/api/Session?api-version=1.0",
                    dataFunc: (r) => r.expiresIn,
                    errorMessage: "Failed to get session"
                });
            },

            refreshSessionAsync: function () {
                return getAsync({
                    url: "/api/Session/Refresh?api-version=1.0",
                    dataFunc: (r) => r.token,
                    errorMessage: "Failed to refresh session"
                });
            },

            createAccountAsync: function (username, emailAddress, password) {
                return postAsync({
                    url: "/api/PrimaryAccounts?api-version=1.0",
                    dataObj: { username: username, emailAddress: emailAddress, password: password },
                    dataFunc: (r) => r,
                    errorMessage: "Failed to create account"
                });
            },

            createNoteAsync: function (secondaryAccountId, title, description) {
                return postAsync({
                    url: "/api/Notes?api-version=1.0",
                    dataObj: { secondaryAccountId: secondaryAccountId, title: title, description: description },
                    dataFunc: (r) => r.noteId,
                    errorMessage: "Failed to create note"
                });
            },

            createSecondaryAccountAsync: function (username, accountName, password, url) {
                return postAsync({
                    url: "/api/SecondaryAccounts?api-version=1.0",
                    dataObj: { username: username, accountName: accountName, password: password, url: url },
                    dataFunc: (r) => r.id,
                    errorMessage: "Failed to create account"
                });
            },

            deleteSecondaryAccountAsync: function (secondaryAccountId) {
                return deleteAsync({
                    url: "/api/SecondaryAccounts?api-version=1.0",
                    dataObj: { secondaryAccountId: secondaryAccountId },
                    dataFunc: (r) => r,
                    errorMessage: "Failed to delete account"
                });
            },

            generatePasswordAsync: function (queryObj) {
                const array = [
                    { s: queryObj.passwordLength, p: "length" },
                    { s: queryObj.upper, p: "upper" },
                    { s: queryObj.number, p: "number" },
                    { s: queryObj.special, p: "special" },
                    { s: "1.0", p: "api-version" }
                ];

                const queryString = buildQueryParameters(array);

                return getAsync({
                    url: "/api/Password?" + queryString,
                    dataFunc: (r) => r.password,
                    errorMessage: "Failed to generate password"
                });
            },

            loadSecondaryAccountsAsync: function () {
                return getAsync({
                    url: "/api/PrimaryAccounts/SecondaryAccounts?api-version=1.0",
                    dataFunc: (r) => r.accounts,
                    errorMessage: "Failed to load accounts"
                });
            },

            loadSecondaryAccountAsync: function (secondaryAccountId) {
                return getAsync({
                    url: `/api/SecondaryAccounts/${secondaryAccountId}?api-version=1.0`,
                    dataFunc: (r) => r,
                    errorMessage: "Failed to load account "
                });
            },

            loadSecondaryAccountNotesAsync: function (secondaryAccountId) {
                return getAsync({
                    url: `/api/SecondaryAccounts/${secondaryAccountId}/Notes?api-version=1.0`,
                    dataFunc: (r) => r.notes,
                    errorMessage: "Failed to load notes"
                });
            },

            loginAsync: function (username, password) {
                return postAsync({
                    url: "/api/PrimaryAccounts/Login?api-version=1.0",
                    dataObj: { emailAddress: username, password: password },
                    dataFunc: (r) => r,
                    errorMessage: "Failed to login"
                });
            },

            logoutAsync: function () {
                return getAsync({
                    url: "/api/PrimaryAccounts/Logout?api-version=1.0",
                    dataFunc: () => {
                        window.sessionStorage.removeItem("master-password-token");
                    },
                    errorMessage: "Failed to logout"
                });
            },

            updateNoteAsync: function (noteId, secondaryAccountId, title, description) {
                return patchAsync({
                    url: `/api/Notes/${noteId}?api-version=1.0`,
                    dataObj: { noteId: noteId, secondaryAccountId: secondaryAccountId, title: title, description: description },
                    dataFunc: (r) => r.noteId,
                    errorMessage: "Failed to update note"
                });
            },

            updateSecondaryAccountAsync: function (obj) {
                return patchAsync({
                    url: `/api/SecondaryAccounts/${obj.secondaryAccountId}?api-version=1.0`,
                    dataObj: obj,
                    dataFunc: (r) => r,
                    errorMessage: "Failed to update secondary account"
                });
            }
        };
    });