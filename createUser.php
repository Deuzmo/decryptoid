<?php // createUser.php
   require_once 'interface.php';
   
   $errors = 0;

   echo "<div style = \"border-style:ridge; width:40%; padding:20px; margin: 0 auto\">";
   if (attemptedCreation()){
      
      $username = getPOST($conn, 'username');
      $email = getPOST($conn, 'email');
      $tmpPw = getPOST($conn, 'pw');
      $tmpPw2 = getPost($conn, 'pwVerify');

      if (!validUser($username)){
         echo "<h4 style = 'color:red'>Username does not comply with requirements</h4>";
         $errors++;
      }
      if (!uniqueUser($conn, $userTable, $username)){
         echo "<h4 style = 'color:red'>Username not available</h4>";
         $errors++;
      }
      if (!validEmail($email)){
         echo "<h4 style = 'color:red'>Email does not comply with requirements</h4>";
         $errors++;
      }
      if ($tmpPw != $tmpPw2){
         echo "<h4 style = 'color:red'>Password and verification didn't match</h4>";
         $errors++;
      }
      if ($errors == 0){
         $success = insertUser($conn,$userTable,$username,$email,$tmpPw);
         if ($success){
            echo "<h4 style = 'color:green'>Account created succesfully!, <a href=authenticate.php>click here</a> to log in.";
            echo "<br> Or, <a href=guestLanding.php>click here</a> to go back to the homepage.</h4>";
            echo "</div>"; //Closes the open div which contains the ridge.
         }
         else {
            $errors = 0;
            echo "<h4 style = 'color:red'>Something went wrong! Try again later.</h4>";
            echo "</div>"; //Closes the open div which contains the ridge.
         }
      }
   }

   if (!attemptedCreation() || attemptedCreation() && $errors > 0){
      echo <<<_END
         <p style= "margin: 25 auto;">Enter the necessary details below to create your account:</p>
         <form action="createUser.php" method="post" enctype='multipart/form-data'>

            <div style = "margin-top:20px; margin-bottom:5px">Username (only digits / letters / '_' / '-'):</div>
            <input type="text" name="username" placeholder="example_123" required><br>

            <div style = "margin-top: 20px; margin-bottom:5px">Email:</div>
            <input type="text" name="email" placeholder="ex.45@aol.com" required><br>

            <div style = "margin-top:20px; margin-bottom:5px">Password (Minimum 8 characters):</div>
            <input type="password" name="pw" required minlength="8"><br>

            <div style = "margin-top:20px; margin-bottom:5px">Verify password</div>
            <input type="password" name="pwVerify" required minlength="8"><br>

            <input type="submit" style = "margin: 20 auto;" value= "Create Account">
         </form>
         <form style="width:100%;" action="guestLanding.php" method="post" enctype='multipart/form-data'>
            <input style="display:block; margin: 0 auto;" type="submit" value="Go back">
         </form>
      </div>
_END;
   }
?>