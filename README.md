This Project can work only **linux debian base** .
**Insatllation**

```bash
# Follow this command
./install.sh
./run.sh
```


```sql
create table alert (
	timestamp char(20) not null,
	src_ip varchar(256) not null,
	src_port int not null,
	dst_ip varchar(256),
	dst_port int not null,
	protocol varchar(16),
	attack_type varchar(8),
	prob float
)
```