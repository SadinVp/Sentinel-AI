const imgs = [
  "static/images/image1.jpg",
  "static/images/image2.jpg",
  "static/images/image3.jpg",
  "static/images/image4.jpg"
];
let idx = 0;
setInterval(() => {
  idx = (idx + 1) % imgs.length;
  document.getElementById('hero-img').src = imgs[idx];
}, 1000);
