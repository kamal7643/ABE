package BSWABE;

import java.util.ArrayList;

import it.unisa.dia.gas.jpbc.Element;

public class BswabePolicy {
	/* serialized */
	
	/* k=1 if leaf, otherwise threshould */
	int k;
	/* attribute string if leaf, otherwise null */
	String attr;
	Element c;			/* G_1 only for leaves */
	Element cp;		/* G_1 only for leaves */
	/* array of BswabePolicy and length is 0 for leaves */
	BswabePolicy[] children;
	
	/* only used during encryption */
	BswabePolynomial q;

	/* only used during decription */
	boolean satisfiable;
	int min_leaves;
	int attri;
	ArrayList<Integer> satl = new ArrayList<Integer>();
	
	public int simplify(String file_attrs) {
		int rem = 0;
		if(children==null || children.length==0) {
			String attrs[] = file_attrs.split(" ");
			for(int i=0; i<attrs.length; i++) {
//				System.out.println(attr.equals(attrs[i]));
				if(attr.equals(attrs[i])) {k--;rem++;}
			}
		}else {
			for(int i=0; i<children.length; i++) {
				rem = children[i].simplify(file_attrs);
				k-=rem;
				rem=0;
			}
		}
//		System.out.println(this.k);
		return rem;
	}
}
