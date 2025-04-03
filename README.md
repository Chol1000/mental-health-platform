# Mental Health Website

---

### Introduction

This document provides a comprehensive overview of the **Mental Health Website** project, including its system architecture, backend implementation, API documentation, user manual, and setup instructions. The backend is developed using Python Flask and integrates various features to support user interactions, journaling, check-ins, progress tracking, and AI-powered mental health support.

---

### Problem Background

Mental health is becoming a global concern. Approximately 1 in 4 people worldwide will develop a mental illness during their lifetime, and over 350 million are affected by depression. It is estimated that nearly 75% of individuals suffering from mental illnesses do not avail themselves of treatment due to financial or social restrictions. While the incidence of mental illnesses is high, access to effective and timely mental health care remains limited. Traditional mental health support systems are hindered by stigma, unaffordability, and unavailability.

To address these challenges, there is a growing need for accessible, interactive, and easy-to-use platforms that provide personalized mental health care and information to help individuals manage their emotional well-being.

---

### Solution Statement

This project proposes the development of an interactive web-based mental health website designed to provide individualized advice, suggestions, and recommendations to improve one's mental health. The website will suggest activities, mindfulness exercises, and wellness strategies tailored to a user's emotional state, powered by AI.

Unlike therapy or clinical diagnosis services, the website is intended as a self-help tool that can be freely accessed by anyone. The platform is designed to help users, regardless of their socioeconomic background, manage their mental health.

---

### Who is Affected?

- Individuals suffering from mental health challenges (stress, anxiety, depression, etc.)
- People seeking self-care solutions for emotional well-being
- Youth and students experiencing academic stress
- Working professionals facing burnout

---

### System Architecture

---

#### Overview

The system follows a **client-server** architecture where the frontend interacts with the Flask backend via RESTful APIs. The backend includes user authentication, data storage, and AI-driven interactions.

---

#### Components

- **Frontend**: Javascript, HTML, and CSS
- **Backend**: Python Flask
- **Database**: SQLite / PostgreSQL
- **AI Integration**: OpenAI API for chatbot responses
- **Logging & Debugging**: Python logging module

---

#### Data Flow Diagram

*(Insert your data flow diagram here)*

---

#### Data Flow Explanation

1. **User Interaction**: The user interacts with the web interface (frontend) by logging in, making journal entries, or chatting with the AI.
2. **API Request**: The frontend sends requests to the Flask backend using API endpoints (e.g., user authentication, mood check-ins).
3. **Backend Processing**: The Flask server processes requests, interacts with the database, and applies any AI responses (via OpenAI API).
4. **Data Storage & Retrieval**: User data, journal entries, and mood check-ins are stored in the database and retrieved when needed.
5. **Response to Frontend**: The backend sends a structured response (JSON format) to update the frontend interface.
6. **User Feedback & Community Interaction**: Users can engage with the community section, and feedback is logged for future improvements.

---

### Technical Specifications

---

#### Backend Features

- User authentication and profile management
- Journal entry system
- Mood check-ins and progress tracking
- AI-powered chatbot with emotional support
- Feedback submission
- Admin debugging tools

---

#### Technology Stack

- **Language**: Python
- **Framework**: Flask
- **Database**: SQLAlchemy ORM
- **API Integration**: OpenAI API for AI chatbot
- **Security**: Password hashing, session management

---

### API Documentation

---

#### User Management

- **Register User** (POST /api/register): Creates a new user account.
- **Login User** (POST /api/login): Authenticates a user and starts a session.
- **Update Profile** (PUT /api/user/<user_id>): Updates user profile details.
- **Delete Account** (DELETE /api/user/<user_id>): Deletes a user account permanently.

---

#### Journal System

- **Create Journal Entry** (POST /api/journal): Allows users to log journal entries.
- **Get Journal Entries** (GET /api/journal/<user_id>): Retrieves journal history for a user.

---

#### Mood Check-ins

- **Submit Check-in** (POST /api/checkins): Logs a user's mood and optional notes.

---

#### Progress Tracking

- **Get Progress** (GET /api/progress/<user_id>): Fetches historical mood metrics.

---

#### AI Chatbot

- **Chat with AI** (POST /api/chat): Processes user messages with emotion-aware responses.

---

#### Feedback Submission

- **Submit Feedback** (POST /api/feedback): Logs user feedback with emotions.

---

### User Manual

---

#### How to Use the Application

1. **Login or Register**:  
   - New users must create an account by providing basic details.  
   - Returning users log in using their credentials.

2. **Accessing the Feeling Menu**:  
   - After logging in, users are presented with a “Feeling Menu” where they can select their current emotional state. Each feeling links to suggested activities designed to support mental well-being.

3. **Exploring Personalized Activities**:  
   - Based on the selected feeling, users receive activity recommendations, including journaling, guided breathing exercises, or engaging with the AI chatbot.

4. **Journaling and Progress Tracking**:  
   - Users can log journal entries to reflect on their emotions. Mood check-ins track emotional progress over time.

5. **Using the AI Chatbot**:  
   - Users can interact with an AI-powered chatbot to receive supportive conversations. The chatbot provides insights, coping strategies, and general encouragement based on user input.

6. **Community and Feedback**:  
   - Users can participate in discussion forums (if available) and provide feedback on their experience.

---

### Setup Instructions

---

#### Prerequisites

- Install **Python 3.8+**
- Install **Flask** and dependencies
- Set up **OpenAI API key** (if using AI chatbot)
- Initialize the database

---

#### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/Chol1000/mental-health-platform.git
   cd backend
- pip install -r requirements.txt
- flask db upgrade
- flask run

#### Deployment

**Hosting Options**:

- Heroku
- AWS EC2
- DigitalOcean
- Render
- Netlify

#### Environment Variables:

**Ensure the following environment variables are set**:

- Database URL
- Secret Key
- OpenAI Key

#### GitHub Repository & Collaboration

The codebase is hosted on GitHub, ensuring version control through branches, pull requests, and issue tracking. Team members have actively contributed via commits and collaboration tools.

**GitHub Repository:**
[https://github.com/Chol1000/mental-health-platform.git]

#### Team Roles and Participation

- **Chol Atem Giet Monykuch:** Backend Implementation, Database Management
- **Mika Rurangwa:** UI/UX Designing, User Testing
- **Kakooza Mahad:** User Experience Design, Application Logic Development
- **Abraham Chan Deng:** Research and Documentation, UI and Feedback Analysis

#### Demo Video
- Here is the Link to Demo Video: [https://drive.google.com/file/d/1ZSXmwNg901G_yXyDRwdEhM1SKlhg_zOn/view]

#### Conclusion

This project integrates mental health tracking, journaling, and AI-based assistance to provide users with a comprehensive support system. The backend ensures data security and provides efficient RESTful endpoints for seamless interaction.

