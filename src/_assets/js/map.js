document.addEventListener('DOMContentLoaded', function() {
    // Get all map buttons
    const mapButtons = document.querySelectorAll('#svg-map a.button');
    
    // Add click event to each button
    mapButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get the id of the clicked state
            const stateId = this.id;
            
            // Hide all contact info divs
            document.querySelectorAll('#dadosMapa > div').forEach(div => {
                div.style.display = 'none';
            });
            
            // Show the contact info div for the clicked state
            const contactDiv = document.querySelector(`#dadosMapa .${stateId}`);
            if (contactDiv) {
                contactDiv.style.display = 'block';
            }
            
            // Highlight the selected state (optional)
            mapButtons.forEach(btn => {
                btn.classList.remove('active');
            });
            this.classList.add('active');
        });
    });
    
    // Also handle jQuery click events for backward compatibility
    if (typeof jQuery !== 'undefined') {
        jQuery(".button").on("click", function () {
            if (jQuery(this).is(".hasContent")) {
                var id = jQuery(this).attr('id');
                jQuery('.display').hide();
                jQuery('.' + id).show();
            }
        });
    }
});
