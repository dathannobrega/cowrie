CREATE TABLE IF NOT EXISTS `urls` (
  `id` int(11) NOT NULL auto_increment,
  `url` text NOT NULL,
  `first_view` datetime NULL,
  `last_view` datetime NULL,
  PRIMARY KEY (`id`)
) ;
