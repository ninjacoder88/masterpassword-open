let appVersion = document.getElementById("app-version");

requirejs.config({
    urlArgs: appVersion.value,
    baseUrl: "/js/lib",
    paths: {
        knockout: "knockout-3.5.0.min",
        jquery: "jquery-3.6.3.min",
        bootstrap: "bootstrap.bundle-5.1.3.min",
        httpService: "httpService-1.0.0",
        text: "text-2.0.16",
        alertModal: "alert-modal/alert-modal",
        pubsub: "pubsub-1.0.0"
    }
});