$(".faq header").click(function(){
	if($("#content" + $(this).attr('id')).css("display") == "block") {
		$("#content" + $(this).attr('id')).slideUp();
	}
	else {
		$(".faq div").slideUp();
		$("#content" + $(this).attr('id')).slideDown();
	}
});

$(document).ready(function() { 
    $(".scroll").click(function(event){        
        event.preventDefault();
        $('html,body').animate({scrollTop:$(this.hash).offset().top}, 800);
   });
});