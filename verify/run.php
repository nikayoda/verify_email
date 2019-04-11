<?php
require('verify.php');

$db = new PDO("mysql:host=dbhost;dbname=verification_next", 'nika', 'passkey');


while(true)
{
  $q = $db->query('SELECT * FROM  `full` WHERE `checked` = "0" AND `checking` != "1" LIMIT 1');
  $q->setFetchMode(PDO::FETCH_ASSOC);
  $res = $q->fetch();
  $i = $res['id'];
  if(!$i) break;

  $reject = false;
  $v = $db->query('SELECT `id`,`mail` FROM  `full` WHERE `id` = "'.
    $i.'" AND `checked` = "0" AND `checking` != "1" AND has_error = "0"');

  $v->setFetchMode(PDO::FETCH_ASSOC);
  $data = $v->fetch();

  if($data){

      $record = $data;
      $db->query('UPDATE full SET checking = "1" WHERE `id` = "'.$record['id'].'"');

      $from = 'sender@hubgrid.io';
      $email = strtolower(trim($record['mail']));

      $validator = new Verify($email, $from);
      $smtp_results = $validator->validate();

      $smtp_result_data = implode("\r\n",array_filter(explode("\r\n", $smtp_results['output'])));

      foreach(explode("\r\n",$smtp_result_data) as $reference => $error)
      {
        foreach (["551 ","552 ","553 ","554 "] as $key => $code) {

          if(preg_match('/'.$code.'/',$error))
          {
            $db->query('UPDATE full SET checking = "0", checked = "1", has_error = "1", header_error = "'.
              $error.'" WHERE `id` = "'.$record['id'].'"');
            $reject = true;
            break;
          }

        }

      }
      if(!$reject)
      {
        if($validator->failed)
        {

             $db->query('UPDATE full SET checking = "0", checked = "1", has_error = "1", header_error = "down" WHERE `id` = "'.
              $record['id'].'"');

        }else{
          if($smtp_results[$email] == 1)
          {
             $db->query('UPDATE full SET valid = "1", checking = "0", checked = "1", headers = "'.
              $smtp_result_data.'" WHERE `id` = "'.$record['id'].'"');
          }else{
             $db->query('UPDATE full SET valid = "2", checking = "0", checked = "1", headers = "'.
              $smtp_result_data.'" WHERE `id` = "'.$record['id'].'"');
          }
        }

      }

  }

}
