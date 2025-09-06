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
            } else {
                // If no specific contact info, show a default message
                console.log('No contact information found for state: ' + stateId);
            }
            
            // Highlight the selected state
            mapButtons.forEach(btn => {
                btn.classList.remove('active');
                // Reset fill color
                const paths = btn.querySelectorAll('path');
                paths.forEach(path => {
                    path.setAttribute('fill', 'none');
                });
            });
            
            // Add active class to clicked state
            this.classList.add('active');
            
            // Change fill color of the clicked state
            const paths = this.querySelectorAll('path');
            paths.forEach(path => {
                path.setAttribute('fill', '#0056b3');
            });
            
            // Smooth scroll to contact info if on mobile
            if (window.innerWidth < 768) {
                document.querySelector('#dadosMapa').scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
        
        // Add hover effects
        button.addEventListener('mouseenter', function() {
            if (!this.classList.contains('active')) {
                const paths = this.querySelectorAll('path');
                paths.forEach(path => {
                    path.setAttribute('fill', '#e6e6e6');
                });
            }
        });
        
        button.addEventListener('mouseleave', function() {
            if (!this.classList.contains('active')) {
                const paths = this.querySelectorAll('path');
                paths.forEach(path => {
                    path.setAttribute('fill', 'none');
                });
            }
        });
    });
    
    // Set a default state to be active on page load (e.g., São Paulo)
    const defaultState = document.querySelector('#svg-map a#saopaulo');
    if (defaultState) {
        defaultState.click();
    }
});
