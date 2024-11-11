document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.movie').forEach(movie => {
        const video = movie.querySelector('video');
        const poster = movie.querySelector('img');

        if (video && poster) {
            // Set initial state: show poster, hide video
            video.style.display = 'none';
            poster.style.display = 'block';

            // Event listener for clicking to play video
            movie.addEventListener('click', () => {
                poster.style.display = 'none';
                video.style.display = 'block';
                video.play();
            });

            // Event listener for mouseleave to reset to poster
            movie.addEventListener('mouseleave', () => {
                video.pause();
                video.currentTime = 0;
                video.style.display = 'none';
                poster.style.display = 'block';
            });
        }
    });
});

//DASHBOARD-----------------------------------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function () {
    const logoutLink = document.getElementById('logoutLink');
    const userNameElement = document.getElementById('userName');
    
    if (userNameElement) {
        fetchUserDetails();
    }

    if (logoutLink) {
        logoutLink.addEventListener('click', function (event) {
            event.preventDefault();
            performLogout();
        });
    }
});

async function fetchUserDetails() {
    try {
        const response = await fetch('/user-details', { credentials: 'include' });

        if (!response.ok) {
            throw new Error('Failed to fetch user details.');
        }

        const data = await response.json();
        console.log(data);

        if (data.success && document.getElementById('userName')) {
            document.getElementById('userName').textContent = data.user.name;
        } else {
            console.error('Failed to fetch user details:', data.message);
        }
    } catch (error) {
        console.error('Error fetching user details:', error);
    }
}

async function performLogout() {
    try {
        const response = await fetch('/logout', {
            method: 'POST',
            credentials: 'include'
        });

        if (response.ok) {
            window.location.href = 'login.html';
        } else {
            console.error('Logout failed');
        }
    } catch (error) {
        console.error('Error during logout:', error);
    }
}
