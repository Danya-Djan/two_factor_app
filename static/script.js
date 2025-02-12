document.addEventListener("DOMContentLoaded", function () {
    var closeButtons = document.querySelectorAll(".alert-dismissible .close");
    closeButtons.forEach(function (button) {
        button.addEventListener("click", function () {
            var alert = this.parentElement;
            alert.style.display = "none";
        });
    });
}); 