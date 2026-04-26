require(["knockout", "httpService", "bootstrap", "jquery"],
    function (ko, http) {
        "use strict";

        function ViewModel() {
            let self = this;
            self.username = ko.observable("");
            self.emailAddress = ko.observable("");
            self.password = ko.observable("");
            self.confirmPassword = ko.observable("");
            self.createAccountEnabled = ko.observable(true);

            self.createAccount = function () {
                self.createAccountEnabled(false);
                if (self.username() === "")
                    return;

                if (self.emailAddress() === "")
                    return;

                if (self.password() === "")
                    return;

                if (self.confirmPassword() === "")
                    return;

                if (self.password() !== self.confirmPassword())
                    return;

                http.createAccountAsync(self.username(), self.emailAddress(), self.password())
                    .then(() => {
                        window.alert("You account was created succesfully. You will be redirected shortly.");
                        setTimeout(function () {
                            window.location = "/home/index";
                        }, 5000);
                    }).catch(() => {
                        self.createAccountEnabled(true);
                    });
            };
        }

        ko.applyBindings(new ViewModel(), document.getElementById("container"));
    });