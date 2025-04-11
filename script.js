document.addEventListener('DOMContentLoaded', function () {
    const mobileMenuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    const iconHamburger = document.getElementById('icon-hamburger');
    const iconClose = document.getElementById('icon-close');
    const navbar = document.getElementById('navbar');

    mobileMenuButton.addEventListener('click', function () {
        mobileMenu.classList.toggle('hidden');
        iconHamburger.classList.toggle('hidden');
        iconClose.classList.toggle('hidden');
    });

    document.addEventListener('click', function (event) {
        if (!mobileMenu.classList.contains('hidden') && !mobileMenu.contains(event.target) && !mobileMenuButton.contains(event.target)) {
            mobileMenu.classList.add('hidden');
            iconHamburger.classList.remove('hidden');
            iconClose.classList.add('hidden');
        }
    });

    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            navbar.classList.add('bg-transparent-on-scroll');
        } else {
            navbar.classList.remove('bg-transparent-on-scroll');
        }
    });
});



// Live Gradient Animation
const gradient = document.querySelector('.animate-gradient');
let angle = 0;

function animateGradient() {
    angle += 0.2;
    gradient.style.background = `linear-gradient(${angle}deg, #8B5CF6, #3B82F6)`;
    requestAnimationFrame(animateGradient);
}

animateGradient();