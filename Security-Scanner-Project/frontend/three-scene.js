// Three.js Immersive XR Scene - Refractive Glass Spheres

class ImmersiveScene {
    constructor() {
        this.container = document.getElementById('canvas-container');
        this.width = window.innerWidth;
        this.height = window.innerHeight;

        this.scene = new THREE.Scene();
        this.camera = new THREE.PerspectiveCamera(75, this.width / this.height, 0.1, 1000);
        this.renderer = new THREE.WebGLRenderer({
            alpha: true,
            antialias: true,
            powerPreference: "high-performance"
        });

        this.spheres = [];
        this.mouse = new THREE.Vector2();
        this.targetMouse = new THREE.Vector2();

        this.init();
    }

    init() {
        // Setup Renderer
        this.renderer.setSize(this.width, this.height);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        this.container.appendChild(this.renderer.domElement);

        // Camera Position
        this.camera.position.z = 5;

        // Add Lights
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
        this.scene.add(ambientLight);

        const dirLight = new THREE.DirectionalLight(0xffffff, 1);
        dirLight.position.set(5, 5, 5);
        this.scene.add(dirLight);

        const pointLight = new THREE.PointLight(0x667eea, 2, 10);
        pointLight.position.set(-2, 1, 2);
        this.scene.add(pointLight);

        // Create Refractive Spheres
        this.createSpheres();

        // Event Listeners
        window.addEventListener('resize', this.onResize.bind(this));
        window.addEventListener('mousemove', this.onMouseMove.bind(this));

        // Start Loop
        this.animate();
    }

    getGlassMaterial() {
        // Advanced physical material simulating glass
        return new THREE.MeshPhysicalMaterial({
            color: 0xffffff,
            metalness: 0.1,
            roughness: 0.05,
            transmission: 0.95, // Glass-like transparency
            thickness: 1.5, // Refraction thickness
            envMapIntensity: 1.5,
            clearcoat: 1.0,
            clearcoatRoughness: 0.1,
            ior: 1.5, // Index of Refraction for glass
            attenuationColor: new THREE.Color(0x667eea), // Tint color
            attenuationDistance: 2.0
        });
    }

    createSpheres() {
        // Environment Map for reflections (simulated with a cube camera or texture)
        // For simplicity, we use a generated cube map logic if needed, but here reliable standard env

        const geometry = new THREE.IcosahedronGeometry(1, 12); // High detail sphere
        const material = this.getGlassMaterial();

        // Determine sphere count based on screen size
        const count = window.innerWidth < 768 ? 4 : 8;

        for (let i = 0; i < count; i++) {
            const mesh = new THREE.Mesh(geometry, material);

            // Random positions spread out
            mesh.position.set(
                (Math.random() - 0.5) * 10,
                (Math.random() - 0.5) * 6,
                (Math.random() - 0.5) * 4
            );

            // Random scale
            const scale = Math.random() * 0.8 + 0.4;
            mesh.scale.set(scale, scale, scale);

            // Store original position for floating animation
            mesh.userData = {
                originalPos: mesh.position.clone(),
                speed: Math.random() * 0.5 + 0.2,
                floatOffset: Math.random() * Math.PI * 2,
                rotationSpeed: new THREE.Vector3(
                    Math.random() * 0.01,
                    Math.random() * 0.01,
                    Math.random() * 0.01
                )
            };

            this.scene.add(mesh);
            this.spheres.push(mesh);
        }

        // Add a "Hero" sphere in the center focused
        const heroGeo = new THREE.IcosahedronGeometry(1.5, 24);
        const heroMat = this.getGlassMaterial();
        heroMat.attenuationColor = new THREE.Color(0x764ba2);

        this.heroSphere = new THREE.Mesh(heroGeo, heroMat);
        this.heroSphere.position.set(0, 0, 0);
        this.heroSphere.userData = {
            originalPos: new THREE.Vector3(0, 0, 0),
            speed: 0.1,
            floatOffset: 0,
            rotationSpeed: new THREE.Vector3(0.002, 0.005, 0)
        };
        // Only visible on larger screens initially
        if (window.innerWidth > 768) {
            this.scene.add(this.heroSphere);
            this.spheres.push(this.heroSphere);
        }
    }

    onMouseMove(e) {
        // Normalize mouse coordinates -1 to 1
        this.targetMouse.x = (e.clientX / this.width) * 2 - 1;
        this.targetMouse.y = -(e.clientY / this.height) * 2 + 1;
    }

    onResize() {
        this.width = window.innerWidth;
        this.height = window.innerHeight;

        this.camera.aspect = this.width / this.height;
        this.camera.updateProjectionMatrix();

        this.renderer.setSize(this.width, this.height);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    }

    animate() {
        requestAnimationFrame(this.animate.bind(this));

        const time = performance.now() * 0.001;

        // Smooth mouse dampening
        this.mouse.x += (this.targetMouse.x - this.mouse.x) * 0.05;
        this.mouse.y += (this.targetMouse.y - this.mouse.y) * 0.05;

        // Animate Spheres
        this.spheres.forEach((sphere, i) => {
            const data = sphere.userData;

            // Floating motion (Sine wave)
            sphere.position.y = data.originalPos.y + Math.sin(time * data.speed + data.floatOffset) * 0.5;

            // Mouse parallax effect - move away from cursor (magnetic repulsion) or parallax
            // Here we do parallax: move slightly opposite to mouse
            const parallaxX = this.mouse.x * (sphere.position.z + 5) * 0.5;
            const parallaxY = this.mouse.y * (sphere.position.z + 5) * 0.5;

            sphere.position.x = data.originalPos.x + parallaxX;
            sphere.rotation.x += data.rotationSpeed.x;
            sphere.rotation.y += data.rotationSpeed.y;
        });

        // Render
        this.renderer.render(this.scene, this.camera);
    }
}

// Initialize Scene
window.addEventListener('DOMContentLoaded', () => {
    new ImmersiveScene();
});
