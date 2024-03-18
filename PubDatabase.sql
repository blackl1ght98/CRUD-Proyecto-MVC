create database Pub;
use Pub;
create table Brand(
BrandId int identity(1,1) primary key not null,
Name varchar(100),
);
create table Beer(
BeerId int identity(1,1) primary key not null,
Name varchar(100),
BrandId int,
constraint FK_BrandId foreign key (BrandId) references Brand(BrandId)
)
INSERT INTO Brand (Name) VALUES ('Minerva');
INSERT INTO Brand (Name) VALUES ('Erdinger');
INSERT INTO Brand (Name) VALUES ('Modern Times');
INSERT INTO Brand (Name) VALUES ('Cruzcampo');