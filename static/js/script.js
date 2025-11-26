document.querySelector("form").addEventListener("submit", function () {
    document.getElementById("spinner").classList.remove("d-none");
});

const switchBtn = document.getElementById('darkSwitch');
switchBtn.addEventListener('change', () => {
    document.body.classList.toggle('bg-dark');
    document.body.classList.toggle('text-light');
    document.body.classList.toggle('text-dark');
});


document.addEventListener('DOMContentLoaded', function() {
    const clipboardItems = document.querySelectorAll('.list-group-item[onclick]');
    
    clipboardItems.forEach(item => {
        item.addEventListener('click', function() {
            const originalBackground = this.style.backgroundColor;
            this.style.backgroundColor = '#d4edda';
            
            setTimeout(() => {
                this.style.backgroundColor = originalBackground;
            }, 300);
        });
    });
});