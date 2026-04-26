require(["knockout", "httpService", "bootstrap", "jquery"],
    function (ko, http) {
        "use strict";

        function ViewModel() {
            const self = this;
            self.loggingIn = ko.observable(false);
            self.username = ko.observable("");
            self.password = ko.observable("");
            self.errorMessage = ko.observable("");
            self.hasError = ko.computed(function () {
                return self.errorMessage() !== "";
            }, this);

            let element = document.getElementById("container");
            if (element !== null) {
                element.addEventListener("keyup", function (event) {
                    if (event.keyCode === 13 || event.key === "Enter") {
                        //document.getElementById("btn-login").click();
                        self.login();
                    }
                });
            }

            self.login = function () {
                self.loggingIn(true);
                self.errorMessage("");

                http.loginAsync(self.username(), self.password())
                    .then((response) => {
                        window.sessionStorage.setItem("master-password-token", response.token);
                        window.location = "/accounts";
                    }).catch(error => {
                        self.errorMessage(error);
                        self.loggingIn(false);
                    });
            };
        }

        ko.applyBindings(new ViewModel(), document.getElementById("container"));
    });