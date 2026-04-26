define(["bootstrap", "text!alert-modal/alert-modal.html"],
    function (bs, html) {
        "use strict";

        var modalsElement = document.getElementById("modals");
        modalsElement.innerHTML = html;

        return {
            self: this,

            showModal: function (message) {
                //var titleElement = document.getElementById("alert-modal-title");
                var messageElement = document.getElementById("alert-modal-message");

                //if (obj.title) {
                //    titleElement.innerText = obj.title;
                //}
                //if (obj.message) {
                    messageElement.innerText = message;
                //}

                let alertModal = new bs.Modal(document.getElementById("alert-modal"));
                alertModal.show();
            }
        };
    });