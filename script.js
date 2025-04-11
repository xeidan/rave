document.addEventListener('DOMContentLoaded', function () {
    const animatedElements = document.querySelectorAll('[data-animate]');

    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const element = entry.target;
          const animation = element.dataset.animate;
          const delay = element.dataset.delay || 0;

          element.style.transition = 'opacity 1000ms ease-out, transform 1000ms ease-out';
          element.style.transitionDelay = `${delay}ms`;
          element.style.opacity = '1';
          element.style.transform = 'translateY(0)';

          observer.unobserve(element);
        }
      });
    }, { threshold: 0.1 });

    animatedElements.forEach(element => {
      element.style.opacity = '0';
      element.style.transform = 'translateY(20px)';
      observer.observe(element);
    });

    const container = document.getElementById('starfield');
    for (let i = 0; i < 100; i++) {
      const star = document.createElement('div');
      const size = Math.random() * 2 + 1;
      star.className = 'star';
      star.style.width = `${size}px`;
      star.style.height = `${size}px`;
      star.style.top = `${Math.random() * 100}%`;
      star.style.left = `${Math.random() * 100}%`;
      star.style.animationDuration = `${1.5 + Math.random() * 2}s, ${15 + Math.random() * 10}s`;
      star.style.animationDelay = `${Math.random() * 5}s, ${Math.random() * 10}s`;
      container.appendChild(star);
    }
  });