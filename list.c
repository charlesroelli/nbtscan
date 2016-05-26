#include <stdio.h>
#include "list.h"
#include <stdlib.h>
#include "errors.h"

extern int quiet;

struct list* new_list() {
	struct list* lst;

	if( ( lst = (struct list*) malloc(sizeof(struct list)) )==NULL ) 
		err_die("Malloc failed", quiet);
	lst->head = NULL;
	return lst;
};

struct list_item* new_list_item(unsigned long content) {
	struct list_item* lst_item;

	if( (lst_item = (struct list_item*) malloc(sizeof(struct list_item)) )==NULL  )
		err_die("Malloc failed", quiet);

	lst_item->next = NULL;
	lst_item->prev = NULL;
	lst_item->content = content;
	return lst_item;
};

void delete_list(struct list* list) {
	struct list_item* pointer;
	
	pointer = list->head;

        if (pointer) {
	   while(pointer->next) pointer = pointer->next; /* Find last list element */

	   /* Go back from tail to head deleteing list items on the way */
   	   while(pointer->prev) {
		pointer = pointer->prev;
		free(pointer->next);
	   };
   	   free(pointer);
        }
	free(list);
};
	
int compare(struct list_item* item1, struct list_item* item2) {
	if(item2==NULL) return ERROR;
	if(item1==NULL) return 1;
	if(item1->content == item2->content) return 0;
	if(item1->content > item2->content) return 1;
	if(item1->content < item2->content) return -1;
};

int insert(struct list* lst, unsigned long content) {

	struct list_item *temp_item, *item;
	int cmp;

	item = new_list_item(content);
	
	cmp = compare(lst->head, item);
	if(lst->head==NULL) {
		lst->head=item;
		return 1;
	} else if (cmp==1) {
		item->next=lst->head;
		lst->head = item;
		item->prev = NULL;
		return 1;
	} else if (cmp==0) {
		free(item);
		return 0;
	} else if (cmp==-1) {
		temp_item = lst->head;
		while(compare(temp_item->next, item)==-1) {
			temp_item = temp_item->next;
		}
		/* temp_item points to last list element less then item */
		/* we shall insert item after temp_item */
		if(compare(temp_item->next, item)==0) {
			free(item);
			return 0;
		} else if(compare(temp_item->next, item)==ERROR) {
			free(item);
			return ERROR;
		} else if(compare(temp_item->next, item)==1) {
			item->next=temp_item->next;
			item->prev=temp_item;
			if(temp_item->next) temp_item->next->prev = item;
			temp_item->next = item;
			return 1;
		};
	} else if (compare(lst->head, item)==ERROR) {
		free(item);
		return ERROR;
	};
};

int in_list(struct list* lst, unsigned long content) {
	struct list_item *temp_item, *item;
        int cmp;

	item = new_list_item(content);
	if(lst->head==NULL) return 0;
	temp_item=lst->head;
	
	while(compare(temp_item, item) < 0) temp_item = temp_item->next;
	if (compare(temp_item, item)==0) return 1;
	return 0;
};
