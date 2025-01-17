﻿# Codebreaker
(Developer: Adam Sandham)

![Mockup image](documents/reactive_mockup.png)

[Live webpage](https://github.com/Sandham-a/ms3-character-folio)

## Table of Content

1. [Project Goals](#project-goals)
    1. [User Goals](#user-goals)
    2. [Site Owner Goals](#site-owner-goals)
2. [User Experience](#user-experience)
    1. [Target Audience](#target-audience)
    2. [User Requirements and Expectations](#user-requirements-and-expectations)
    3. [User Stories](#user-stories)
    4. [Site Owner Stories](#site-owner-stories)
3. [Design](#design)
    1. [Design Choices](#design-choices)
    2. [Colour](#colours)
    3. [Fonts](#fonts)
    4. [Structure](#structure)
    5. [Wireframes](#wireframes)
4. [Technologies Used](#technologies-used)
    1. [Languages](#languages)
    2. [Frameworks & Tools](#frameworks-&-tools)
5. [Features](#features)
6. [Testing](#validation)
    1. [HTML Validation](#HTML-validation)
    2. [CSS Validation](#CSS-validation)
    3. [JavaScript Validation](#javascript-validation)
    4. [Accessibility](#accessibility)
    5. [Performance](#performance)
    6. [Device testing](#performing-tests-on-various-devices)
    7. [Browser compatibility](#browser-compatability)
    8. [Testing user stories](#testing-user-stories)
8. [Bugs](#Bugs)
9. [Deployment](#deployment)
    1. [EmailJS API](#emailjs-api)
10. [Credits](#credits)
11. [Acknowledgments](#acknowledgments)

## Project Goals 
The aim of this project is to showcase python and flask development in relation to web application development.

### User Goals
- To create/view/delete/ edit basic Dungeon and Dragons (DnD) character templates.
- To view a catalogue of characters that have been developed by the rest of the users on the site. 

### Site Owner Goals
- Creating an engaging site that allows people the create characters for their DnD games.
- Create a system that talks to mongoDB and stores the information in a non relational database and is able to retrieve and edit information when needed

## User Experience

### Target Audience
- DnD players looking for somewhere to store their character ideas
- Dungeon Masters that are looking for inspiration in regards to characters to use in their campaigns.   

### User Requirements and Expectations
- A simple and intuitive site to navigate.
- A site that allows users to an account and password.
- A site secure enough that allows only them to delete and and edit their characters.
- Functions and Links work as expected.
- A website that looks like it was produced professionally.
- An easy way to leave feedback.
- Accessibility.

### User Stories
1. As a user, I want to be able to create a DnD character and have it stored.
2. As a user, I wish to be able to access any character I create at a later date.
3. As a user, I wish to be able to edit any character I create and be able to update the information. 
4. As a user, I wish to be able to delete any character I create as if I no longer need it.
5. As a user, I wish to know that the system is secure that only I can edit or delete characters that I've created.

### Site Owner Stories
6. As a site owner, I want users to be able to contact us for suggestions about how to improve the game.
7. As a site owner, I want users to be able to find us on social media.

## Design

### Design Choices
The site was designed to highlight the medieval themes whilst also giving a clean and professional display 

### Colour
The colors where simply going to be chosen a black and white. As they provide a stark contrast and will improve the aria contrast score 

### Fonts
The font for the title was Ruthie as it has the balance of being a handwriting script whilst also being amongst the more legible scripts available as part of google fonts

### Structure
The page is structured in a obvious and user-friendly manner. Upon arriving at the website the user starts at the log on screen. Which will clearly have the option to register an account at the bottom of the page

- From there it will load their profile page that will have the following options
    - To see all the characters that users has been created
    - To be able to edit the characters that they have created
    - To be able to delete

### Wireframes

- Due to the way the game is laid out it is not necessary to alter the design layout for desktop and table and only minor alteration will need to be made for mobile screens

<details><summary>Opening Screen</summary>
<img src="documents/wireframes/opening_screen.png">
</details>
<details><summary>Opening Screen Mobile</summary>
<img src="documents/wireframes/opening_screen_mobile.png">
</details>
<details><summary>Instructions</summary>
<img src="documents/wireframes/instructions.png">
</details>
<details><summary>Instructions Mobile</summary>
<img src="documents/wireframes/instructions_mobile.png">
</details>
<details><summary>Difficulty Screen</summary>
<img src="documents/wireframes/level_selector.png">
</details>
<details><summary>Difficulty Screen Mobile</summary>
<img src="documents/wireframes/level_selector_mobile.png">
</details>
<details><summary>Game Setup</summary>
<img src="documents/wireframes/game_setup.png">
</details>
<details><summary>Game Setup Mobile</summary>
<img src="documents/wireframes/game_setup_mobile.png">
</details>
<details><summary>Game Wrong Answer</summary>
<img src="documents/wireframes/game_wrong_answer.png">
</details>
<details><summary>Game Wrong Answer Mobile</summary>
<img src="documents/wireframes/game_wrong_answer_mobile.png">
</details>
<details><summary>Game Success</summary>
<img src="documents/wireframes/game_success.png">
</details>
<details><summary>Game Success Mobile</summary>
<img src="documents/wireframes/game_success_mobile.png">
</details>
<details><summary>Game Failure</summary>
<img src="documents/wireframes/game_failure.png">
</details>
<details><summary>Game Success Mobile</summary>
<img src="documents/wireframes/game_failure_mobile.png">
</details>
<details><summary>Contact Page</summary>
<img src="documents/wireframes/contact_page.png">
</details>
<details><summary>Contact Page Mobile</summary>
<img src="documents/wireframes/contact_page_mobile.png">
</details>
<details><summary>404 page</summary>
<img src="documents/wireframes/404_page.png">
</details>
<details><summary>404 page Mobile</summary>
<img src="documents/wireframes/404_page_mobile.png">
</details>

## Technologies Used

### Languages
- HTML
- CSS
- JavaScript

### Frameworks & Tools
- Bootstrap
- Git
- GitHub
- Gitpod
- Balsamiq
- Font Awesome
- JSHint
- Lighthouse
- W3C Markup validation service
- W3C Jigsaw CSS validation service 
- WAVE WebAIM web accessibility evaluation tool
- EmailJS

## Features
The site consists of three pages and nine features

### Game Area
- Featured on one page.
- This area holds the entire game and instructions on how to play the game.
- As the player makes choices different elements will become visible and other will be hidden.

<details><summary>Game Area</summary>
<img src="documents/features/game_area.png">
</details>

### Footer
- Featured on all pages
- Consists of a section providing social media links and a link to the contact form
- User story covered: 4

<details><summary>Footer</summary>
<img src="documents/features/footer_bar.png">
</details>

### Mobile Footer
- When being used on smaller screens the footer bar will react and change to show the contact me page as an icon rather than just words
- User story covered: 5

<details><summary>Footer Mobile</summary>
<img src="documents/features/footer_bar_mobile.png">
</details>

### Login Screen
- User enters a name that is there agent name and responded to as such through the game.
- User story covered: 1

<details><summary>Login Screen</summary>
<img src="documents/features/name_entry.png">
</details>

### Difficulty Selection

- User clicks on a button that sets up the number of possible colors that will be used in the game 
- Easy will have 16 possible combinations, medium will have 256 possible combinations and hard will have 1296 possible combinations  

<details><summary>Difficulty Screen</summary>
<img src="documents/features/difficulty_selector.png">
</details>

### Game over screen
- Consists of three sections
    - The game over message with the solution to the puzzle
    - Button to restart the game
    - User stories covered: 4

<details><summary>Game Over Screen</summary>
<img src="documents/features/game_over_screen.png">
</details>

### Correct guess screen
- Consists of four sections
    - The congratulatory message
    - A button to restart the game
    - User story covered: 5

<details><summary>Correct Guess screen</summary>
<img src="documents/features/correct_guess_screen.png">
</details>

### Contact form
- A way for the user to provide feedback
- User story covered 7 

<details><summary>Contact Form</summary>
<img src="documents/features/contact_form.png">
</details>

### Form confirmation
- Provides the user with feedback after the form has been submitted and a button to return to the game
- User story covered: 6

<details><summary>Form confirmation</summary>
<img src="docs/features/feature-form-confirmation.jpg">
</details>

### 404 message
- Provides the user with a way to return to the game after clicking on a broken link

<details><summary>404 message</summary>
<img src="documents/features/404_screen.png">
</details>

## Validation

### HTML Validation
The W3C Markup Validation Service was used to validate the HTML of the website. All pages pass with no errors no warnings to show.
<details><summary>Home</summary>
<img src="documents/validation/html_validation_index.png">
</details>
<details><summary>Contact Us</summary>
<img src="documents/validation/html_validation_contact.png">
</details>
<details><summary>404</summary>
<img src="documents/validation/html_validation_404.png">
</details>

### CSS Validation
The W3C Jigsaw CSS Validation Service was used to validate the CSS of the website. The CSS past without causing any major errors.

<details><summary>style.css</summary>
<img src="documents/validation/css_validation.png">
</details>

### JavaScript Validation
JSHint Static Code Analysis Tool for JavaScript was used to validate the Javascript files. No significant issues were found and those found were more due to the fact it couldn't see the HTML code it was set up to interact with.

<details><summary>game.js</summary>
<img src="documents/validation/js_valid_game.png">
</details>
<details><summary>contact.js</summary>
<img src="documents/validation/js_valid_contact.png">
</details>
<details><summary>404.js</summary>
<img src="documents/validation/js_valid_404.png">
</details>

### Accessibility
The WAVE WebAIM web accessibility evaluation tool was used to ensure the website met high accessibility standards. All pages pass with 0 errors.

<details><summary>Index</summary>
<img src="documents/validation/wave_index.png">
</details>
<details><summary>Contact</summary>
<img src="documents/validation/wave_contact.png">
</details>
<details><summary>404</summary>
<img src="documents/validation/wave_404.png">
</details>

### Performance 
Google Lighthouse in Google Chrome Developer Tools was used to test the performance of the website.

<details><summary>Home</summary>
<img src="documents/lighthouse/lighthouse_index.html.png">
</details>
<details><summary>Contact</summary>
<img src="documents/lighthouse/lighthouse_contact.html.png">
</details>
<details><summary>404</summary>
<img src="documents/lighthouse/lighthouse_404.html.png">
</details>

### Performing tests on various devices 
The website was tested on the following devices:

- 2 Homemade PCs
- ASUS Vivobook K553EA
- Samsung Galaxy Tab A tablet
- Samsung A53 Phone

In addition, the website was tested using the Google Chrome Developer Tools Device Toggling option for all available device options.

### Browser Compatability
The website was tested on the following browsers:

- Google Chrome
- Mozilla Firefox
- Microsoft Edge
- Opera GX Browser

### Testing user stories

1. As a user, I want to enter a username

| **Feature** | **Action** | **Expected Result** | **Actual Result** |
|-------------|------------|---------------------|-------------------|
| Start screen | Enter a user name | The games screen loads with the inputted username | Works as expected |

<details><summary>Screenshots</summary>
<img src="documents/user_stories/user_story_1.png">
</details>

2. As a user, I want to select the difficulty of the puzzle I wish to solve

| **Feature** | **Action** | **Expected Result** | **Actual Result** |
|-------------|------------|---------------------|-------------------|
| Difficulty screen | Click the on the Easy level that will show only grey and white buttons and then onto medium that will show red, green, blue and yellow buttons |  | Works as expected |

<details><summary>Screenshots</summary>
<img src="documents/user_stories/user_story_2.png">
</details>

3. As a user, I want to be able to change the buttons colors by clicking on them

| **Feature** | **Action** | **Expected Result** | **Actual Result** |
|-------------|------------|---------------------|-------------------|
| Game screen | Click on the button to change color | The button to cycle to the next color | Works as expected |

<details><summary>Screenshots</summary>
<img src="documents/user_stories/user_story_3.png">
</details>

4. As a user, I want to know what the correct phrase was in case I don't guess it correctly

| **Feature** | **Action** | **Expected Result** | **Actual Result** |
|-------------|------------|---------------------|-------------------|
| Game Failed Screen | Ran out of guesses | The game over screen with the correct answer is displayed | Works as expected |

<details><summary>Screenshots</summary>
<img src="documents/user_stories/user_story_4.png">
</details>

5. As a user, I want feedback on my correct answers

| **Feature** | **Action** | **Expected Result** | **Actual Result** |
|-------------|------------|---------------------|-------------------|
| Correct guess screen | Solve the puzzle before you run out of guesses | The correct message is displayed | works as expected |

<details><summary>Screenshots</summary>
<img src="documents/user_stories/user_story_5.png">
</details>

6. As a user, I want confirmation that my feedback was sent

| **Feature** | **Action** | **Expected Result** | **Actual Result** |
|-------------|------------|---------------------|-------------------|
| Form confirmation | Fill out the contact form and click the submit button | A thank you message is displayed and the site owner receives the message| Works as expected | 

<details><summary>Screenshots</summary>
<img src="documents/user_stories/user_story_6.png">
</details>

7. As a site owner, I want users to be able to contact us or make suggestions for new phrases.

| **Feature** | **Action** | **Expected Result** | **Actual Result** |
|-------------|------------|---------------------|-------------------|
| Contact form | Scroll down to the footer section and click the contact us link | Displays the contact form | Works as expected |

<details><summary>Screenshots</summary>
<img src="documents/user_stories/user_story_7.png">
</details>

8. As a site owner, I want users to be able to find us on social media.

| **Feature** | **Action** | **Expected Result** | **Actual Result** |
|-------------|------------|---------------------|-------------------|
| Footer | Scroll down to the footer section and click on the required link | The link takes user to the indicated website | Works as expected |

<details><summary>Screenshots</summary>
<img src="documents/user_stories/user_story_8.png">
</details>

## Bugs

| **Bug** | **Fix** |
| ----------- | ----------- |
| Restarted game would cycle through the button colors two at a time | bug was due to the location of the event listeners and each instance of the game would create a new listener so had listener placed outside the function |
| Instructions button wouldn't toggle though logic was correct | Though the logic was correct as the button had an onlick attribute and an event listener it lead to them cancelling each other out |
| Failed game would result in the next game failing right away | make sure the counter is reset when it clicked |
| Color black for the buttons is difficult to see on the background | switched the available colors from black to grey |
| Background image would not fill the entire screen | used CSS to alter the attributes of the body tag |
| Resetting the game resulted in the last game showing on screen| rewrote the reset function to make sure that all games are cleared |
| On mobile screens the footer bar would only take the first column and not allow access to the contact page | added another icon and coded it to appear when the screen was a mobile level |
| The contact page unusable on smaller screens | Change padding and margin sizes for smaller screens |

## Deployment
The website was deployed using GitHub Pages by following these steps:
1. In the GitHub repository navigate to the Settings tab
2. On the left-hand menu select Pages
3. For the source select Branch: master
4. After the webpage refreshes automatically you will ses a ribbon on the top saying: "Your site is published at https://sandham-a.github.io/ms2-codebreaker-game/

You can fork the repository by following these steps:
1. Go to the GitHub repository
2. Click on Fork button in the upper right hand corner

You can clone the repository by following these steps:
1. Go to the GitHub repository 
2. Locate the Code button above the list of files and click it 
3. Select if you prefer to clone using HTTPS, SSH, or Github CLI and click the copy button to copy the URL to your clipboard
4. Open Git Bash
5. Change the current working directory to the one where you want the cloned directory
6. Type git clone and paste the URL from the clipboard ($ git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY)
7.Press Enter to create your local clone.

### EmailJS API
1. Create an account at emailjs.com
2. Add new email service, make note of the contact_service id
3. Add a new email template, make note of the contact_form id
4. Go the the integration dashboard, make note of your user id
5. Load the EmailJS SDK in the head of your HTML file
6. In JavaScript create a function that listens to a submit event and then initializes the SDK with your user id (emailjs.init('YOUR_USER_ID');) and submits the form (emailjs.sendForm('contact_service', 'contact_form', this);)

## Credits
All images, save the background image were created by the developer.

### Media
- [background image]('./static/images/background_image.jpg'): DnD Fight Scene 
By: Tam's Patkos 
<a href='https://www.artstation.com/artwork/R30glA'> https://www.artstation.com/artwork/R30glA</a>
- [Safe Icon]('./assets/images/safe_icon.png')  Mourad Mokrane from the <a href='https://thenounproject.com/icon/safe-1343380/'>noun project</a>

### Code

- CSS for background image opacity https://css-tricks.com/snippets/css/transparent-background-images/
- Email sending JavaScript API code was written with the help of the official EmailJS tutorial https://www.emailjs.com/docs/tutorial/creating-contact-form/

## Acknowledgments
I would like to take the opportunity to thank:
- My mentor Mo Shami for his feedback, advice, guidance and support.
- My girlfriend Nicola for allowing me time to do this project with my precious weekends with her.
- THe code institute tutor for providing me with help for some of my trickier problems.
- My parents who own gave me child free time to work on this project.