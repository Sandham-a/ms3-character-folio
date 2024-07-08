$(document).ready(function(){
    $('.sidenav').sidenav({edge: "left"});
    $('.collapsible').collapsible();
    $('.tooltipped').tooltip();
    $('select').formSelect();
  });

function sendMail(contactForm) {
    emailjs.send("service_0fp6dju", "template_k9hm21e", {
        "from_name": contactForm.name.value,
        "from_email": contactForm.email.value,
        "message": contactForm.message.value
    })
    .then(
        function(response) {
              console.log("SUCCESS", response);
              alert("Thank you for your email. Your suggestion will be considered.");
              location.reload();
        },
        function(error) {
            console.log("FAILED", error);
            alert("I'm sorry there seems to have been an issue with sending this message please try again")
        }
    );
    return false;  // To block from loading a new page
  }