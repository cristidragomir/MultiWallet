create table Users (
    id serial primary key,
    email varchar(255),
    username varchar(255),
    hashed_password bytea
    session_token varchar(30)
);

create table Wallet (
    id serial primary key,
    w_name varchar(255),
    w_address varchar(255),
    w_type varchar(10), -- MX or ETH
    owner_id int,
    constraint fk_user foreign key(owner_id) references Users(id) on delete cascade on update cascade
);