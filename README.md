# Travel Catalog

This is a travel catalog web App powered by Flask framework.

This app allows authenticated user to create their favorite destinations.

This web App display travel spots categorized by region.

This is developed with *Top-Down method* referencing Udacity FullStack Foundations
(https://www.udacity.com/course/viewer#!/c-ud088-nd)

## Environment

  - OS: win7 x64
  - python modules
      - python 2.7.6
      - Flask (0.9)
      - httplib2 (0.9.2)
      - oauth2client (1.5.2)
      - requests (2.2.1)
      - SQLAlchemy (0.8.4)

## How to Run
  - Configure VM

      - Install VirtualBox
      - Install Vagrant

  - Launch VM

      - clone this project
      - open bash under project root folder
      - ```$ vagrant up #boot vm```
      - ```$ vagrant ssh #login vm```

  - Run server in vagrant ssh terminal

```shell
vagrant@vagrant-ubuntu-trusty-32:~$ cd ../../vagrant/
vagrant@vagrant-ubuntu-trusty-32:~$python catalog_server.py
* Running on http://0.0.0.0:5000/
* Restarting with reloader

```

  - Browse Webpage by entering http://127.0.0.1:5000 in browser

  - Logout ssh, Shutdown VM
      - ```vagrant@vagrant-ubuntu-trusty-32:~$ exit # logout ssh```
      - ```$ vagrant halt```

## Notes: Milestones of this project

- ckecklist (Top-Down Approach, Front-End to Back-End):
    - Mock-up: design mock-up and url format for each pages
        - goal: sharable
    - Routing: Flask code to achieve url routing (even page is no content )
        - goal: correct routing functionality
    - Template, Forms: import HTML template
        - goal: correct template display
    - CRUD functionality: implement CRUD operation
        - goal: correct CRUD Operation
    - API Endpoint: API functionality
        - goal: pass client request test
    - Styling, Message Flashing: add css,js,message flashing
        - goal: polished page style and message flashing
    - OAuth Implementation
        - user login, logout from 3rd party OAuth server
        - protect create/edit/delete permission from visitor
    - Local Permission System
        - create User table and data schema
        - modify processes of login and creating new data
        - add public template
        - use alert message to protect url attack
    - Styling Refinements
        - data integrity
        - login page
        - login link
