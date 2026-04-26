require(["knockout", "httpService", "alertModal", "bootstrap", "pubsub", "jquery"],
    function (ko, http, modal, bootstrap, ps) {
        "use strict";

        function AccountField(obj) {
            const self = this;
            self.eid = obj.eid;
            self.accountId = obj.id;
            self.title = obj.title;
            self.value = ko.observable(obj.value);
            self.editing = ko.observable(false);

            self.copy = function () {
                let element = document.getElementById(self.eid);
                element.select();
                element.setSelectionRange(0, 500);
                document.execCommand("copy");
                //resetTimeout();
                //checkSession();
            };

            self.edit = function () {
                self.editing(true);
                //resetTimeout();
                //checkSession();
            };

            self.save = function () {
                self.editing(false);
                //resetTimeout();
                //checkSession();
                http.updateSecondaryAccountAsync({ secondaryAccountId: self.accountId, fieldName: self.title, value: self.value() })
                    .then(() => {

                    }).catch(error => {
                        modal.showModal(error);
                    });
            };

            self.cancel = function () {
                self.editing(false);
                //resetTimeout();
                //checkSession();
            };
        }

        function Note(obj) {
            const self = this;
            self.id = obj.id;
            self.secondaryAccountId = obj.secondaryAccountId;
            self.title = ko.observable(obj.title);
            self.details = ko.observable(obj.description);
            self.editing = ko.observable(false);

            function createNote() {
                http.createNoteAsync(self.secondaryAccountId, self.title(), self.details())
                    .then(noteId => {
                        self.id = noteId;
                    }).catch(error => {
                        modal.showModal(error);
                    });
            }

            function saveNote() {
                http.updateNoteAsync(self.id, self.secondaryAccountId, self.title(), self.details())
                    .then(noteId => {
                        self.id = noteId;
                    }).catch(error => {
                        modal.showModal(error);
                    });
            }

            self.copy = function () {
                let element = document.getElementById(self.id);
                element.select();
                element.setSelectionRange(0, 500);
                document.execCommand("copy");
                //resetTimeout();
                //checkSession();
            };

            self.edit = function () {
                self.editing(true);
                //resetTimeout();
                //checkSession();
            };

            self.save = function () {
                self.editing(false);
                if (self.id === undefined) {
                    createNote();
                } else {
                    saveNote();
                }
                //resetTimeout();
                //checkSession();
            };

            self.cancel = function () {
                self.editing(false);
                //resetTimeout();
                //checkSession();
            };
        }

        function Account(obj) {
            const self = this;
            self.xid = obj.xid;
            self.id = obj.id;
            self.favicon = obj.favicon;
            self.accountName = new AccountField({ eid: "accountname-" + self.xid, id: self.id, title: "AccountName", value: obj.accountName });
            self.category = new AccountField({ eid: "category-" + self.xid, id: self.id, title: "Category", value: obj.category });
            self.username = new AccountField({ eid: "username-" + self.xid, id: self.id,  title: "Username", value: "" });
            self.password = new AccountField({ eid: "password-" + self.xid, id: self.id,  title: "Password", value: "" });
            self.url = new AccountField({ eid: "url-" + self.xid, id: self.id,  title: "URL", value: "" });
            self.notes = ko.observableArray([]);
            self.expanded = ko.observable(false);
            let detailsLoaded = false;
            
            self.launch = function () {
                loadDetails();
                ps.publish("account-selected", this);
                let accountModal = new bootstrap.Modal(document.getElementById("accountModal"));
                accountModal.show();
                //resetTimeout();
                //checkSession();
            };

            function loadDetails() {
                if (detailsLoaded === true) {
                    return;
                }

                let accountLoaded = false;
                let notesLoaded = false;
                http.loadSecondaryAccountAsync(self.id)
                    .then(account => {
                        self.username.value(account.username);
                        self.password.value(account.password);
                        self.url.value(account.url);
                        accountLoaded = true;
                        detailsLoaded = accountLoaded && notesLoaded;
                    }).catch(error => {
                        modal.showModal(error);
                    });

                http.loadSecondaryAccountNotesAsync(self.id)
                    .then(notes => {
                        notes.forEach(note => {
                            note.secondaryAccountId = self.id;
                            self.notes.push(new Note(note));
                        });
                        notesLoaded = true;
                        detailsLoaded = accountLoaded && notesLoaded;
                    }).catch(error => {
                        modal.showModal(error);
                    });
            }

            self.addNote = function () {
                let note = new Note({ secondaryAccountId: self.id, title: "", description: "" });
                note.editing(true);
                self.notes.push(note);
                //resetTimeout();
                //checkSession();
            };

            self.deleteAccount = function () {
                ps.publish("delete-account-clicked", { account: self });
            };

            self.deleteNote = function (note) {
                if (note.id === undefined) {
                    self.notes.remove(note);
                    return;
                }
                //resetTimeout();
                //TODO: push to database
                //checkSession();
            };

            self.openSite = function () {
                if (self.url.value() === undefined || self.url.value() === null) {
                    return;
                }
                window.open(self.url.value());
                //resetTimeout();
                //checkSession();
            };
        }

        function ViewModel() {
            const self = this;
            let secondaryAccounts = [];
            self.accountName = ko.observable("");
            self.username = ko.observable("");
            self.password = ko.observable("");
            self.url = ko.observable("");
            self.upper = ko.observable(false);
            self.number = ko.observable(false);
            self.lower = ko.observable(true);
            self.special = ko.observable(false);
            self.plength = ko.observable(20);
            self.addAccountEnabled = ko.observable(true);
            self.accounts = ko.observableArray([]);
            self.visibleAccounts = ko.observableArray([]);
            self.filterText = ko.observable("");
            self.categories = ko.observableArray([]);
            self.selectedCategory = ko.observable();

            self.selectedCategory.subscribe(function (newValue) {
                if (newValue === null || newValue === undefined) {
                    self.accounts(secondaryAccounts);
                    return;
                }
                const currentValue = newValue.toLowerCase();
                const filterAccounts = [];
                secondaryAccounts.forEach(account => {
                    const category = account.category.value().toLowerCase();
                    if (category.indexOf(currentValue) !== -1) {
                        filterAccounts.push(account);
                    }
                });
                self.accounts(filterAccounts);
            });

            self.selectedAccount = ko.observable();
            ps.subscribe("account-selected", (account) => {
                self.selectedAccount(account);
            });

            ps.subscribe("delete-account-clicked", (message) => {
                self.deleteAccount(message.account);
            });

            let newXid = 10000000;

            const filterTextElement = document.getElementById("filter-text");
            filterTextElement.addEventListener("keyup", () => {
                const currentValue = filterTextElement.value.toLowerCase();
                if (currentValue === "") {
                    self.accounts(secondaryAccounts);
                    return;
                }
                const filterAccounts = [];
                secondaryAccounts.forEach(account => {
                    const accountName = account.accountName.value().toLowerCase();
                    if (accountName.indexOf(currentValue) !== -1) {
                        filterAccounts.push(account);
                    }
                });
                self.accounts(filterAccounts);
            });

            function loadSecondaryAccounts() {
                self.accounts([]);
                secondaryAccounts = [];
                const categories = [];
                http.loadSecondaryAccountsAsync()
                    .then(accounts => {
                        let xid = 0;
                        accounts.forEach(account => {
                            account.xid = xid++;

                            if (account.category === null || account.category === undefined) {
                                account.category = "Uncategorized";
                            }
                            if (account.category === "") {
                                account.category = "Uncategorized";
                            }

                            if (categories.indexOf(account.category) === -1) {
                                categories.push(account.category);
                            }

                            secondaryAccounts.push(new Account(account));
                        });
                        self.accounts(secondaryAccounts);
                        self.categories(categories.sort());
                        //resetTimeout();
                    }).catch(error => {
                        modal.showModal(error);
                    });
            }

            function checkSession() {
                http.checkSessionAsync()
                    .then(expiresIn => {
                        if (expiresIn <= 0) {
                            window.location.href = "home/logout";
                            return;
                        }

                        if (expiresIn < 120) {
                            let sessionModal = new bootstrap.Modal(document.getElementById("sessionModal"));
                            sessionModal.show();
                        }
                    }).catch(error => {
                        console.error(error);
                    });
            }

            self.addAccount = function () {
                self.addAccountEnabled(false);

                http.createSecondaryAccountAsync(self.username(), self.accountName(), self.password(), self.url())
                    .then(id => {
                        self.accounts.push(new Account({
                            xid: newXid++,
                            id: id,
                            accountName: self.accountName(),
                            username: self.username(),
                            password: self.password(),
                            url: self.url(),
                        }));

                        self.accountName("");
                        self.username("");
                        self.password("");
                        self.url("");
                    }).finally(() => {
                        self.addAccountEnabled(true);
                        //resetTimeout();
                    });
            };

            self.deleteAccount = function (account) {      
                let confirm = window.confirm("Are you sure you want to delete this account?");

                if (confirm === true) {
                    http.deleteSecondaryAccountAsync(account.id)
                        .then(() => {
                            self.accounts.remove(account);
                            //resetTimeout();
                        }).catch(error => {
                            modal.showModal(error);
                        });
                }
            };

            self.generate = function () {
                http.generatePasswordAsync({
                    passwordLength: self.plength(),
                    upper: self.upper(),
                    number: self.number(),
                    special: self.special()
                }).then(password => {
                    self.password(password);
                    //resetTimeout();
                }).catch(error => {
                    modal.showModal(error);
                });
            };

            self.continueSession = function () {
                http.refreshSessionAsync()
                    .then(token => {
                        window.sessionStorage.setItem("master-password-token", token);
                    }).catch(error => {
                        console.error(error);
                    });
            };

            function initialize() {
                loadSecondaryAccounts();
                //resetTimeout();
                //checkSession();
                window.setInterval(() => {
                    checkSession();
                }, 1000 * 90);
            }

            initialize();
        }

        ko.applyBindings(new ViewModel(), document.getElementById("container"));
    });