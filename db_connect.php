<?php

#database connection variables
$dbhost =  "localhost";
$dbusername = "";
$dbpassword = "";
$dbname = "";



try {
 #database connection
  $mysqli = new mysqli($dbhost, $dbusername, $dbpassword, $dbname);
  
  $mysqli->set_charset("utf8mb4");

  #if error then catch and show error
    } catch(Exception $excep) {

          error_log($excep->getMessage()); //error message for error log
  	      exit('Error connecting to database'); //show user error message
    }



if(!@$_SESSION){ session_start(); };

