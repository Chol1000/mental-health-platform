// Display current date
function updateCurrentDate() {
  const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
  const today = new Date();
  document.getElementById('currentDate').textContent = today.toLocaleDateString('en-US', options);
}

// Initialize all functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  updateCurrentDate();
  setupModals();
  fetchUserData();
  setupCheckinForm();
  setupJournalForm();
  setupEditProfileForm();
  
  // Update chart when time range changes
  const timeRange = document.getElementById('timeRange');
  if (timeRange) {
      timeRange.addEventListener('change', fetchProgressData);
  }
});

// Modal functionality
function setupModals() {
  // Get all modal close buttons
  const closeButtons = document.querySelectorAll('.close-modal, .close-btn');
  
  // Close modal when clicking X
  closeButtons.forEach(button => {
      button.addEventListener('click', function() {
          const modal = this.closest('.modal');
          if (modal) {
              modal.style.display = 'none';
          }
      });
  });
  
  // Close modal when clicking outside
  window.addEventListener('click', function(event) {
      if (event.target.classList.contains('modal')) {
          event.target.style.display = 'none';
      }
  });
  
  // Daily Check-in Card
  const dailyCheckinCard = document.getElementById('dailyCheckinCard');
  if (dailyCheckinCard) {
      dailyCheckinCard.addEventListener('click', function(e) {
          e.preventDefault();
          document.getElementById('checkinModal').style.display = 'block';
      });
  }
  
  // Journal Card
  const journalCard = document.getElementById('journalCard');
  if (journalCard) {
      journalCard.addEventListener('click', function(e) {
          e.preventDefault();
          document.getElementById('journalModal').style.display = 'block';
      });
  }
  
  // Progress Card
  const progressCard = document.getElementById('progressCard');
  if (progressCard) {
      progressCard.addEventListener('click', function(e) {
          e.preventDefault();
          document.getElementById('progressModal').style.display = 'block';
          fetchProgressData();
      });
  }
  
  // Edit Profile Link
  const editProfileLink = document.getElementById('editProfileLink');
  if (editProfileLink) {
      editProfileLink.addEventListener('click', function(e) {
          e.preventDefault();
          document.getElementById('editProfileModal').style.display = 'block';
      });
  }

  // Logout Link
  const logoutLink = document.getElementById('logoutLink');
  if (logoutLink) {
      logoutLink.addEventListener('click', function(e) {
          e.preventDefault();
          localStorage.removeItem('user');
          window.location.href = '../../signup/signup.html';
      });
  }

  // Delete Account Link
  const deleteAccountLink = document.getElementById('deleteAccountLink');
  if (deleteAccountLink) {
      deleteAccountLink.addEventListener('click', function(e) {
          e.preventDefault();
          document.getElementById('deleteAccountModal').style.display = 'block';
      });
  }

  // Confirm Delete Button
  const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
  if (confirmDeleteBtn) {
      confirmDeleteBtn.addEventListener('click', async function() {
          const userData = localStorage.getItem('user');
          if (!userData) {
              alert('No user data found');
              return;
          }

          try {
              const user = JSON.parse(userData);
              const response = await fetch(`https://mental-health-platform-pro4.onrender.com/api/user/${user.id}`, {
                  method: 'DELETE'
              });
              const result = await response.json();
              
              if (result.success) {
                  localStorage.removeItem('user');
                  window.location.href = '../login/login.html';
              } else {
                  alert('Failed to delete account: ' + result.message);
              }
          } catch (error) {
              console.error('Error:', error);
              alert('An error occurred while deleting account');
          }
      });
  }
}

// Fetch user data from localStorage and display name
function fetchUserData() {
  const userData = localStorage.getItem('user');
  
  if (userData) {
      try {
          const user = JSON.parse(userData);
          
          // Display user's first name
          if (document.getElementById('userFirstName')) {
              document.getElementById('userFirstName').textContent = user.first_name;
          }
          
          // Set user ID in forms
          if (document.getElementById('userId')) {
              document.getElementById('userId').value = user.id;
          }
          if (document.getElementById('journalUserId')) {
              document.getElementById('journalUserId').value = user.id;
          }
          if (document.getElementById('editProfileUserId')) {
              document.getElementById('editProfileUserId').value = user.id;
          }
          
          // Pre-fill edit profile form
          if (document.getElementById('editFirstName')) {
              document.getElementById('editFirstName').value = user.first_name;
          }
          if (document.getElementById('editLastName')) {
              document.getElementById('editLastName').value = user.last_name;
          }
          if (document.getElementById('editEmail')) {
              document.getElementById('editEmail').value = user.email;
          }
          
          // Check if user has checked in today
          checkTodaysCheckin(user.id);
          
      } catch (e) {
          console.error('Error parsing user data:', e);
          // If error parsing, redirect to login
          window.location.href = '../login/login.html';
      }
  } else {
      // If no user data found, redirect to login
      window.location.href = '../login/login.html';
  }
}

async function checkTodaysCheckin(userId) {
  try {
      const response = await fetch(`https://mental-health-platform-pro4.onrender.com/api/progress/${userId}?time_range=day&metric_type=mood`);
      const data = await response.json();
      
      if (data.success && data.today) {
          document.getElementById('currentMoodDisplay').textContent = `Your mood today: ${data.today.mood}`;
      }
  } catch (error) {
      console.error('Error checking today\'s check-in:', error);
  }
}

// Submit check-in form
function setupCheckinForm() {
  const checkinForm = document.getElementById('checkinForm');
  if (checkinForm) {
      checkinForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          
          // Reset errors
          resetFormErrors(checkinForm);

          // Get form data
          const formData = {
              user_id: document.getElementById('userId').value,
              mood: document.getElementById('mood').value,
              energy_level: document.getElementById('energyLevel').value,
              anxiety_level: document.getElementById('anxietyLevel').value,
              notes: document.getElementById('notes').value
          };

          // Validation
          let isValid = true;
          if (!formData.mood) {
              showError('mood', 'Please select your mood');
              isValid = false;
          }
          if (!formData.energy_level) {
              showError('energyLevel', 'Please set your energy level');
              isValid = false;
          }

          if (!isValid) return;

          try {
              const response = await fetch('https://mental-health-platform-pro4.onrender.com/api/checkins', {
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/json',
                  },
                  body: JSON.stringify(formData)
              });
              
              const result = await response.json();
              
              if (result.success) {
                  showSuccessMessage(checkinForm, 'Check-in submitted successfully!');
                  
                  // Update today's mood display
                  document.getElementById('currentMoodDisplay').textContent = `Your mood today: ${formData.mood}`;
                  
                  setTimeout(() => {
                      checkinForm.reset();
                      document.getElementById('checkinModal').style.display = 'none';
                  }, 2000);
              } else {
                  showError('mood', result.message || 'Check-in failed');
              }
          } catch (error) {
              console.error('Error:', error);
              showError('mood', 'An error occurred. Please try again.');
          }
      });
  }
}

// Submit journal form
function setupJournalForm() {
  const journalForm = document.getElementById('journalForm');
  if (journalForm) {
      journalForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          
          // Reset errors
          resetFormErrors(journalForm);

          const formData = {
              user_id: document.getElementById('journalUserId').value,
              title: document.getElementById('entryTitle').value.trim(),
              content: document.getElementById('entryContent').value.trim(),
              mood: document.getElementById('entryMood').value,
              is_private: document.getElementById('isPrivate').checked
          };

          // Validation
          let isValid = true;
          if (!formData.title) {
              showError('entryTitle', 'Title is required');
              isValid = false;
          }
          if (!formData.content) {
              showError('entryContent', 'Content is required');
              isValid = false;
          }

          if (!isValid) return;

          try {
              const response = await fetch('https://mental-health-platform-pro4.onrender.com/api/journal', {
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/json',
                  },
                  body: JSON.stringify(formData)
              });
              
              const result = await response.json();
              
              if (result.success) {
                  showSuccessMessage(journalForm, 'Journal entry saved!');
                  
                  setTimeout(() => {
                      journalForm.reset();
                      document.getElementById('journalModal').style.display = 'none';
                  }, 2000);
              } else {
                  showError('entryTitle', result.message || 'Failed to save entry');
              }
          } catch (error) {
              console.error('Error:', error);
              showError('entryTitle', 'An error occurred. Please try again.');
          }
      });
  }
}

// Fetch and display progress data
async function fetchProgressData() {
  const userData = localStorage.getItem('user');
  if (!userData) {
      window.location.href = '../login/login.html';
      return;
  }

  const user = JSON.parse(userData);
  const timeRange = document.getElementById('timeRange') ? document.getElementById('timeRange').value : 'week';
  
  try {
      const response = await fetch(`https://mental-health-platform-pro4.onrender.com/api/progress/${user.id}?time_range=${timeRange}&metric_type=mood`);
      const data = await response.json();
      
      if (data.success) {
          // Update today's status display
          const todayDisplay = document.getElementById('todayMoodDisplay');
          if (todayDisplay) {
              if (data.today) {
                  todayDisplay.textContent = `Your mood today: ${data.today.mood || 'No specific mood recorded'}`;
              } else {
                  todayDisplay.textContent = 'No check-in yet today';
              }
          }
          
          // Render chart if container exists
          if (document.getElementById('moodChart')) {
              renderMoodChart(data.historical || []);
          }
          
          // Generate insights
          generateInsights(data.historical || []);
      } else {
          console.error('Error fetching progress data:', data.message);
          const todayDisplay = document.getElementById('todayMoodDisplay');
          if (todayDisplay) todayDisplay.textContent = 'Error loading data';
      }
  } catch (error) {
      console.error('Error:', error);
      const todayDisplay = document.getElementById('todayMoodDisplay');
      if (todayDisplay) todayDisplay.textContent = 'Error loading data';
  }
}

// Render mood chart
function renderMoodChart(metrics) {
  const chartContainer = document.getElementById('moodChart');
  if (!chartContainer) return;
  
  chartContainer.innerHTML = '';
  
  if (metrics.length === 0) {
      chartContainer.innerHTML = '<p>No data available for the selected time period</p>';
      return;
  }

  // Display last 7 entries
  const recentData = metrics.slice(-7);
  const maxValue = 5;
  
  recentData.forEach((data, index) => {
      const date = new Date(data.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      const value = data.value || 3; // Default to neutral if no value
      const barHeight = (value / maxValue) * 100;
      
      const bar = document.createElement('div');
      bar.className = 'chart-bar';
      bar.style.height = `${barHeight}%`;
      bar.innerHTML = `<div class="chart-bar-label">${date}</div>`;
      chartContainer.appendChild(bar);
  });
}

// Generate simple insights
function generateInsights(metrics) {
  const insightsText = document.getElementById('insightsText');
  if (!insightsText) return;
  
  if (metrics.length === 0) {
      insightsText.textContent = "Not enough data yet. Check in daily to see your progress!";
      return;
  }
  
  const values = metrics.map(m => m.value || 3); // Default to neutral if no value
  const avg = (values.reduce((a, b) => a + b, 0) / values.length).toFixed(1);
  
  let trend = "stable";
  if (values.length > 1) {
      const first = values[0];
      const last = values[values.length - 1];
      if (last > first + 0.5) trend = "improving";
      if (last < first - 0.5) trend = "declining";
  }
  
  const insights = `
      Your average mood has been ${avg}/5 over this period.
      <br><br>
      Your mood trend appears to be ${trend}.
      <br><br>
      ${trend === "improving" ? "Great job! Keep up the positive momentum!" : 
          trend === "declining" ? "Consider reaching out for support if this trend continues." :
          "Consistency is key to understanding your mental health patterns."}
  `;
  
  insightsText.innerHTML = insights;
}

function setupEditProfileForm() {
  const editProfileForm = document.getElementById('editProfileForm');
  if (!editProfileForm) return;
  
  editProfileForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      // Reset errors
      resetFormErrors(editProfileForm);

      const formData = {
          id: document.getElementById('editProfileUserId').value,
          first_name: document.getElementById('editFirstName').value.trim(),
          last_name: document.getElementById('editLastName').value.trim(),
          email: document.getElementById('editEmail').value.trim(),
          current_password: document.getElementById('currentPassword').value,
          new_password: document.getElementById('editPassword').value || undefined
      };

      // Validate password if changing
      if (formData.new_password) {
          if (formData.new_password !== document.getElementById('confirmPassword').value) {
              showError('confirmPassword', 'Passwords do not match');
              return;
          }
          
          if (formData.new_password.length < 8) {
              showError('editPassword', 'Password must be at least 8 characters');
              return;
          }
      }

      try {
          const response = await fetch('https://mental-health-platform-pro4.onrender.com/api/user/profile', {
              method: 'PUT',
              headers: {
                  'Content-Type': 'application/json',
              },
              body: JSON.stringify(formData)
          });
          
          const result = await response.json();
          
          if (result.success) {
              // Update local storage with new user data
              const user = {
                  id: result.user.id,
                  first_name: result.user.first_name,
                  last_name: result.user.last_name,
                  email: result.user.email
              };
              localStorage.setItem('user', JSON.stringify(user));
              
              // Update UI
              document.getElementById('userFirstName').textContent = result.user.first_name;
              
              showSuccessMessage(editProfileForm, 'Profile updated successfully!');
              
              // Close modal after 2 seconds
              setTimeout(() => {
                  editProfileForm.reset();
                  document.getElementById('editProfileModal').style.display = 'none';
              }, 2000);
          } else {
              showError('currentPassword', result.message || 'Update failed');
          }
      } catch (error) {
          console.error('Error:', error);
          showError('editEmail', 'An error occurred. Please try again.');
      }
  });
}

// Helper functions
function resetFormErrors(form) {
  const errorMessages = form.querySelectorAll('.error-message');
  errorMessages.forEach(el => {
      el.style.display = 'none';
  });
  
  const inputs = form.querySelectorAll('input, select, textarea');
  inputs.forEach(input => {
      input.classList.remove('error');
  });
}

function showError(fieldId, message) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  
  let errorEl = document.getElementById(`${fieldId}_error`);
  if (!errorEl) {
      errorEl = document.createElement('div');
      errorEl.id = `${fieldId}_error`;
      errorEl.className = 'error-message';
      field.parentNode.appendChild(errorEl);
  }
  
  field.classList.add('error');
  errorEl.textContent = message;
  errorEl.style.display = 'block';
}

function showSuccessMessage(form, message) {
  let successEl = form.querySelector('.success-message');
  if (!successEl) {
      successEl = document.createElement('div');
      successEl.className = 'success-message';
      form.prepend(successEl);
  }
  
  successEl.textContent = message;
  successEl.style.display = 'block';
  
  // Remove after 3 seconds
  setTimeout(() => {
      successEl.style.display = 'none';
  }, 3000);
}
