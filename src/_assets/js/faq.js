// FAQ accordion functionality
document.addEventListener('DOMContentLoaded', function() {
  const faqHeaders = document.querySelectorAll(".faq header");
  
  faqHeaders.forEach(header => {
    header.addEventListener('click', function() {
      const contentId = "content" + this.id;
      const content = document.getElementById(contentId);
      
      if (content.style.display === "block") {
        content.style.display = "none";
        // Optional: Add animation with slideUp effect
        // $(content).slideUp();
      } else {
        // Hide all FAQ content first
        document.querySelectorAll(".faq .faqContent").forEach(el => {
          el.style.display = "none";
        });
        
        // Show the clicked one
        content.style.display = "block";
        // Optional: Add animation with slideDown effect
        // $(content).slideDown();
      }
    });
  });
});
